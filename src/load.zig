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

//! Implementation of Veles 'load' mode for passwords loading.

const std = @import("std");

const tpm = @import("tpm.zig");
pub const common = @import("common.zig");
const keyutils = @import("keyutils.zig");
const passwords = @import("passwords.zig");
const properties = @import("properties.zig");
const zfs = @import("zfs.zig");

const eql = std.mem.eql;
const BUFFER_SIZE = common.BUFFER_SIZE;
const DIGEST_SIZE = common.DIGEST_SIZE;

const VelesError = error{
    LoadKeyFailed,
    TpmMetaMismatch,
};

pub const Options = struct {
    check_only: bool = false,
    help: bool = false,
    input: []const u8 = "veles.json",
    no_fallback: bool = false,
    no_poweroff: bool = true,
    systemd_ask_password: bool = false,

    pub const __messages__ = .{
        .check_only = "Only check the validity of the passwords, don't load into ZFS ",
        .input = "File path to load ZFS verification config from ",
        .no_fallback = "Don't ask the user to type a password if TPM unsealing failed ",
        .no_poweroff = "Skip powering off the system in case of verification failure ",
        .systemd_ask_password = "Use 'systemd-ask-password' for retrieving passwords ",
    };

    pub const __shorts__ = .{
        .check_only = .c,
        .help = .h,
        .input = .i,
        .no_fallback = .n,
        .no_poweroff = .o,
        .systemd_ask_password = .p,
    };
};

fn tryScramblingPcr(tpm_dev: *tpm.Device, pcr_index: u8) void {
    var hash: [DIGEST_SIZE]u8 = undefined;
    std.crypto.random.bytes(&hash);
    tpm.extend(tpm_dev, pcr_index, hash) catch {};
}

pub fn getAllPasswords(
    allocator: std.mem.Allocator,
    input: []const u8,
    systemd_ask_password: bool,
    check_only: bool,
    prompt_if_not_manual: bool,
) !bool {
    // Load verification config.
    var parsed_config = try common.loadVerificationConfig(allocator, input);
    defer parsed_config.deinit();
    const config = parsed_config.value;

    var buf: [BUFFER_SIZE]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);

    for (config.encryption_roots) |enc_root| {
        const keyname = try std.fmt.allocPrintSentinel(allocator, "zfs-{s}", .{enc_root}, 0);
        defer allocator.free(keyname);

        // Check if the password is already present in keyring,
        // can happen if `loadImpl` was partially successful.
        if (keyutils.getPasswordFromKeyring(keyname, &buf)) |_| {
            if (!prompt_if_not_manual or try passwords.isManualPassword(allocator, enc_root)) {
                continue;
            }
        } else |_| {}

        const prompt = try std.fmt.allocPrint(
            allocator,
            "Enter password for encryption root '{s}':",
            .{enc_root},
        );
        defer allocator.free(prompt);
        const Checker = struct {
            allocator: std.mem.Allocator,
            enc_root: []const u8,
            check_only: bool,
            pub fn check(self: *const @This(), password: []const u8) bool {
                zfs.loadKey(self.allocator, self.enc_root, password, self.check_only) catch |err| {
                    std.log.err(
                        "Failed loading the key for encryption root '{s}': {t}",
                        .{ self.enc_root, err },
                    );
                    return false;
                };
                return true;
            }
        };
        const checker: Checker = .{
            .allocator = allocator,
            .enc_root = enc_root,
            .check_only = check_only,
        };
        // Call for side effects of loading the key to ZFS in `check` and
        // storing the password in keyring.
        _ = try passwords.getPassword(
            Checker,
            allocator,
            keyname,
            prompt,
            &buf,
            checker,
            systemd_ask_password,
        );
        try passwords.markPasswordAsManual(allocator, enc_root);
    }

    return true;
}

fn loadImpl(allocator: std.mem.Allocator, opts: Options) !void {
    // Load verification config.
    var parsed_config = try common.loadVerificationConfig(allocator, opts.input);
    defer parsed_config.deinit();
    const config = parsed_config.value;

    // Create TPM.
    var tpm_dev = try tpm.Device.init(config.tpm.device, config.tpm.capabilities);
    defer tpm_dev.deinit();

    if (!common.debug) {
        // Avoid exposing the key.
        errdefer tryScramblingPcr(&tpm_dev, config.extend);
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

    // Extend PCR with configdata hash.
    const config_hash = try properties.getPropertiesHashForAllDatasets(
        allocator,
        datasets_props,
        config.all_datasets,
        config_mounts,
    );
    try tpm.extend(&tpm_dev, config.extend, &config_hash);

    // Unseal and deserialize passwords.
    const serialized_pwds = try tpm.unseal(&tpm_dev, allocator, config.measure, config.slot);
    defer allocator.free(serialized_pwds);
    defer std.crypto.secureZero(u8, @constCast(serialized_pwds));

    // Make passwords unreadable from TPM.
    try tpm.extend(&tpm_dev, config.extend, &.{});

    var pwds = try passwords.deserializePasswords(allocator, serialized_pwds);
    defer common.freeStringsSlice(allocator, &pwds);
    defer common.secureZeroStringsSlice(pwds);

    if (pwds.len != config.encryption_roots.len) {
        std.log.err(
            "Got {d} TPM passwords but {d} encryption roots",
            .{ pwds.len, config.encryption_roots.len },
        );
        return VelesError.TpmMetaMismatch;
    }

    for (0..pwds.len) |idx| {
        const enc_root = config.encryption_roots[idx];
        zfs.loadKey(allocator, enc_root, pwds[idx], opts.check_only) catch {
            std.log.err(
                "Failed loading the key for encryption root '{s}'",
                .{enc_root},
            );
            return VelesError.LoadKeyFailed;
        };
        const keyname = try std.fmt.allocPrintSentinel(
            allocator,
            "zfs-{s}",
            .{enc_root},
            0,
        );
        defer allocator.free(keyname);
        try keyutils.addPasswordToKeyring(keyname, pwds[idx]);
    }
}

pub fn run(allocator: std.mem.Allocator, opts: Options) !void {
    std.log.info("Veles called in 'load' mode", .{});
    loadImpl(allocator, opts) catch |err| {
        if (!opts.no_fallback) {
            if (getAllPasswords(
                allocator,
                opts.input,
                opts.systemd_ask_password,
                opts.check_only,
                false, // prompt_if_not_manual
            )) |_| {
                std.log.warn("Keys loading failed but passwords were provided interactively", .{});
                return;
            } else |_| {
                std.log.err("Keys loading failed and passwords were not provided interactively", .{});
            }
        }
        if (common.debug) {
            std.log.err("Failed to load keys: {t}", .{err});
        } else if (!opts.no_poweroff) {
            common.poweroff(allocator, err, true);
        } else {
            std.log.err("Failed to load keys", .{});
            std.posix.exit(255);
        }
        return;
    };
    std.log.info("Keys loading succeeded", .{});
}
