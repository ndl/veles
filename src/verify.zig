// Veles is a tool to setup and use TPM-based ZFS datasets encryption.
//
// Copyright (C) 2026 Alexander Tsvyashchenko <veles@endl.ch>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Implementation of Veles 'verify' mode for datasets verification.

const std = @import("std");

const common = @import("common.zig");
const datasets = @import("datasets.zig");
const keyutils = @import("keyutils.zig");
const load = @import("load.zig");
const passwords = @import("passwords.zig");
const tpm = @import("tpm.zig");
const zfs = @import("zfs.zig");

const eql = std.mem.eql;
const BUFFER_SIZE = common.BUFFER_SIZE;
const DIGEST_SIZE = common.DIGEST_SIZE;

const VelesError = error{
    DatasetVerificationFailed,
    MountVerificationFailed,
};

pub const Options = struct {
    exclude: []const u8 = "",
    help: bool = false,
    input: []const u8 = "veles.json",
    keep_keys: bool = false,
    no_fallback: bool = false,
    no_poweroff: bool = true,
    systemd_ask_password: bool = false,

    pub const __messages__ = .{
        .exclude = "Comma-separated list of dataset names to exclude from verification ",
        .input = "File path to load ZFS verification config from ",
        .keep_keys = "If true - do not remove keys from the keyring ",
        .no_fallback = "Don't ask the user to type a password if verification failed ",
        .no_poweroff = "Skip powering off the system in case of verification failure ",
        .systemd_ask_password = "Use 'systemd-ask-password' for retrieving passwords ",
    };

    pub const __shorts__ = .{
        .exclude = .e,
        .help = .h,
        .input = .i,
        .keep_keys = .k,
        .no_fallback = .n,
        .no_poweroff = .o,
        .systemd_ask_password = .p,
    };
};

fn verifyImpl(allocator: std.mem.Allocator, opts: Options) !void {
    // Load verification config.
    var parsed_config = try common.loadVerificationConfig(allocator, opts.input);
    defer parsed_config.deinit();
    const config = parsed_config.value;

    // Create TPM.
    var tpm_dev: ?tpm.Device = null;
    if (!eql(u8, config.tpm.device, "none")) {
        tpm_dev = try tpm.Device.init(config.tpm.device, config.tpm.capabilities);
    }
    defer {
        if (tpm_dev != null) tpm_dev.?.deinit();
    }

    var config_mounts: std.StringHashMap([]const u8) = .init(allocator);
    for (config.mounts) |entry| {
        try config_mounts.put(entry[0], entry[1]);
    }
    defer config_mounts.deinit();

    // Get all ZFS datasets properties.
    const json_datasets_props = try zfs.getAllDatasetsProperties(allocator);
    defer json_datasets_props.deinit();
    const datasets_props = json_datasets_props.value.datasets.map;

    // Get target properties to verify.
    var target_props = try zfs.getTargetProperties(allocator);
    defer target_props.deinit();

    // encryption root from configdata -> password:
    var config_enc_roots: std.StringHashMap([]const u8) = .init(allocator);
    defer common.freeStringsMap(allocator, &config_enc_roots);
    defer common.secureZeroStringsMap(&config_enc_roots);

    var pwd_hashes_to_enc_roots = std.StringHashMap([]const u8).init(allocator);
    defer common.freeStringsMap(allocator, &pwd_hashes_to_enc_roots);
    defer common.secureZeroStringsMap(&pwd_hashes_to_enc_roots);

    var pwd_buf: [BUFFER_SIZE]u8 = undefined;
    defer std.crypto.secureZero(u8, &pwd_buf);
    // Retrieve all passwords.
    for (config.encryption_roots) |enc_root| {
        const keyname = try std.fmt.allocPrintSentinel(
            allocator,
            "zfs-{s}",
            .{enc_root},
            0,
        );
        defer allocator.free(keyname);
        const password = try keyutils.getPasswordFromKeyring(keyname, &pwd_buf);
        if (!opts.keep_keys) {
            try keyutils.deletePasswordFromKeyring(keyname);
        }
        try config_enc_roots.put(
            try allocator.dupe(u8, enc_root),
            try allocator.dupe(u8, password),
        );
    }

    var real_mounts = try zfs.getMounts(allocator, opts.exclude);
    defer common.freeStringsMap(allocator, &real_mounts);

    // Verify real mounts match what we expect.
    if (config_mounts.count() != real_mounts.count()) {
        std.log.err("Expected {d} mounts got {d}", .{ config_mounts.count(), real_mounts.count() });
        return VelesError.MountVerificationFailed;
    }

    var it = real_mounts.iterator();
    while (it.next()) |mount_entry| {
        const real_ds_name = mount_entry.key_ptr.*;
        const real_mnt_path = mount_entry.value_ptr.*;

        const config_mnt_path = config_mounts.get(real_ds_name) orelse {
            std.log.err("Unexpected mounted dataset '{s}'", .{real_ds_name});
            return VelesError.MountVerificationFailed;
        };
        if (!eql(u8, config_mnt_path, real_mnt_path)) {
            std.log.err(
                "Dataset '{s}' should be mounted at '{s}' but it is mounted at '{s}'",
                .{ real_ds_name, config_mnt_path, real_mnt_path },
            );
            return VelesError.MountVerificationFailed;
        }

        const ds = datasets_props.get(real_ds_name) orelse {
            std.log.err("Cannot find properties for dataset '{s}'", .{real_ds_name});
            return VelesError.DatasetVerificationFailed;
        };

        const props = ds.properties.map;

        if (props.get("encryptionroot")) |enc_root_entry| {
            const enc_root = enc_root_entry.value;
            const password = config_enc_roots.get(enc_root) orelse {
                std.log.err("Cannot find `encryptionroot` for dataset '{s}'", .{real_ds_name});
                return VelesError.DatasetVerificationFailed;
            };
            if (datasets.verifyMetadataForDataset(
                allocator,
                enc_root,
                real_ds_name,
                real_mnt_path,
                password,
                props,
                target_props,
                &pwd_hashes_to_enc_roots,
            )) |hash| {
                defer allocator.free(hash);
                std.log.info("Dataset '{s}' verification succeeded", .{real_ds_name});
                if (!common.debug and tpm_dev != null) {
                    try tpm.extend(&tpm_dev.?, config.extend, hash);
                }
            } else |_| {
                std.log.err("Dataset '{s}' verification failed", .{real_ds_name});
                return VelesError.DatasetVerificationFailed;
            }
        }
    }
}

fn clearPasswordsFromKeyring(allocator: std.mem.Allocator, input: []const u8) !void {
    // Load verification config.
    var parsed_config = try common.loadVerificationConfig(allocator, input);
    defer parsed_config.deinit();
    const config = parsed_config.value;

    for (config.encryption_roots) |enc_root| {
        const keyname = try std.fmt.allocPrintSentinel(
            allocator,
            "zfs-{s}",
            .{enc_root},
            0,
        );
        defer allocator.free(keyname);
        keyutils.deletePasswordFromKeyring(keyname) catch {};
    }
}

pub fn run(allocator: std.mem.Allocator, opts: Options) !void {
    const sigact = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    // Ignore error: nothing useful we can do about it anyway.
    _ = std.posix.sigaction(std.posix.SIG.INT, &sigact, null);

    std.log.info("Veles called in 'verify' mode", .{});
    verifyImpl(allocator, opts) catch |err| {
        if (!opts.no_fallback) {
            if (load.getAllPasswords(
                allocator,
                opts.input,
                opts.systemd_ask_password,
                true, // check_only
                true, // prompt_if_not_manual
            )) |_| {
                if (!opts.keep_keys) {
                    clearPasswordsFromKeyring(allocator, opts.input) catch {};
                }
                std.log.warn("Verification failed but passwords were provided interactively", .{});
                return;
            } else |_| {
                std.log.err("Verification failed and passwords were not provided interactively", .{});
            }
        }
        if (common.debug) {
            std.log.err("Failed to verify keys: {t}", .{err});
        } else if (!opts.no_poweroff) {
            common.poweroff(allocator, err, false);
        } else {
            std.log.err("Failed to verify keys", .{});
            std.posix.exit(255);
        }
        return;
    };
    std.log.info("Verification succeeded", .{});
}
