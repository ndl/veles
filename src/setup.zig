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

//! Implementation of Veles 'setup' mode for verification setup.

pub const common = @import("common.zig");

const std = @import("std");

const datasets = @import("datasets.zig");
const keyutils = @import("keyutils.zig");
const passwords = @import("passwords.zig");
const properties = @import("properties.zig");
const tpm = @import("tpm.zig");
const zfs = @import("zfs.zig");

const eql = std.mem.eql;
const BUFFER_SIZE = common.BUFFER_SIZE;
const DIGEST_SIZE = common.DIGEST_SIZE;

const TpmInfo = common.TpmInfo;
const VerificationConfig = common.VerificationConfig;

const VelesError = error{
    IncorrectPcrs,
    NoZfsDatasets,
};

pub const Options = struct {
    all_datasets: bool = false,
    exclude: []const u8 = "",
    extend: u8 = 15,
    force: bool = false,
    help: bool = false,
    kdf_iterations: u32 = 1,
    kdf_memory: u32 = 32 * 1024,
    kdf_parallelism: u24 = 1,
    measure: []const u8 = "7,15",
    output: []const u8 = "veles.json",
    slot: u32 = 0,
    systemd_ask_password: bool = false,
    tpm: []const u8 = "/dev/tpmrm0",

    pub const __messages__ = .{
        .all_datasets = "Include all datasets (not just mounted) into properties verification ",
        .exclude = "List of dataset names to assume not mounted ",
        .extend = "PCR to extend ZFS metadata into ",
        .force = "Continue the setup even with non-zero extension PCR ",
        .kdf_iterations = "Argon2 iterations ",
        .kdf_memory = "Argon2 memory, in KB ",
        .kdf_parallelism = "Argon2 parallelism ",
        .measure = "Comma-separated list of PCRs to measure before the key is unsealed ",
        .output = "File path to write verification metadata to ",
        .slot = "TPM persistent handle to use ",
        .systemd_ask_password = "Use 'systemd-ask-password' for retrieving passwords ",
        .tpm = "TPM device to use, 'none' to setup dataset authentification only ",
    };

    pub const __shorts__ = .{
        .all_datasets = .a,
        .exclude = .e,
        .extend = .x,
        .force = .f,
        .help = .h,
        .kdf_iterations = .i,
        .kdf_memory = .r,
        .kdf_parallelism = .l,
        .measure = .m,
        .output = .o,
        .slot = .s,
        .systemd_ask_password = .p,
        .tpm = .t,
    };
};

fn writeVerificationConfig(
    allocator: std.mem.Allocator,
    slot: u32,
    measure: []const u8,
    extend: u8,
    tpm_info: TpmInfo,
    all_datasets: bool,
    encryption_roots: [][]const u8,
    mounts: std.StringHashMap([]const u8),
    output_path: []const u8,
) !void {
    std.log.info("Writing verification config to '{s}'", .{output_path});
    var mounts_list: std.ArrayList([2][]const u8) = .empty;
    defer mounts_list.deinit(allocator);
    var it = mounts.iterator();
    while (it.next()) |entry| {
        try mounts_list.append(allocator, [2][]const u8{ entry.key_ptr.*, entry.value_ptr.* });
    }
    const json_config: VerificationConfig = .{
        .slot = slot,
        .measure = measure,
        .extend = extend,
        .tpm = tpm_info,
        .all_datasets = all_datasets,
        .encryption_roots = encryption_roots,
        .mounts = mounts_list.items,
    };
    var config_file = try std.fs.cwd().createFile(output_path, .{ .mode = 0o600 });
    defer config_file.close();
    var config_buf: [BUFFER_SIZE]u8 = undefined;
    var config_writer = config_file.writer(&config_buf);
    const config_writer_intf = &config_writer.interface;
    var config_stringifier = std.json.Stringify{ .writer = config_writer_intf };
    try config_stringifier.write(json_config);
    try config_writer_intf.flush();
}

fn getPcrsIndices(allocator: std.mem.Allocator, measure: []const u8) ![]const u8 {
    var pcrs: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, measure, ',');
    while (it.next()) |pcr| {
        try pcrs.append(allocator, try std.fmt.parseInt(u8, pcr, 10));
    }
    return pcrs.toOwnedSlice(allocator);
}

pub fn run(allocator: std.mem.Allocator, opts: Options) !void {
    std.log.info("Veles called in 'setup' mode", .{});

    // Get all ZFS datasets properties.
    const json_datasets_props = try zfs.getAllDatasetsProperties(allocator);
    defer json_datasets_props.deinit();
    const datasets_props = json_datasets_props.value.datasets.map;
    if (datasets_props.count() == 0) {
        std.log.err("No ZFS datasets found", .{});
        return VelesError.NoZfsDatasets;
    }

    // Get all ZFS mounts.
    var mounts = try zfs.getMounts(allocator, opts.exclude);
    defer common.freeStringsMap(allocator, &mounts);

    // Calculate and write hashes for all encrypted datasets.
    const kdf_params = std.crypto.pwhash.argon2.Params{
        .t = opts.kdf_iterations,
        .m = opts.kdf_memory,
        .p = opts.kdf_parallelism,
    };
    var enc_roots = try datasets.writeMetadataForAllDatasets(
        allocator,
        datasets_props,
        mounts,
        kdf_params,
        opts.systemd_ask_password,
    );
    defer common.freeStringsMap(allocator, &enc_roots);
    defer common.secureZeroStringsMap(&enc_roots);

    var enc_roots_keys: std.ArrayList([]const u8) = try .initCapacity(allocator, enc_roots.count());
    defer enc_roots_keys.deinit(allocator);
    var enc_roots_it = enc_roots.iterator();
    while (enc_roots_it.next()) |entry| {
        try enc_roots_keys.append(allocator, entry.key_ptr.*);
    }

    if (!eql(u8, opts.tpm, "none")) {
        // Calculate properties verification hash.
        const props_hash = try properties.getPropertiesHashForAllDatasets(
            allocator,
            datasets_props,
            opts.all_datasets,
            mounts,
        );

        // Convert to hex.
        var hex_buf: [BUFFER_SIZE]u8 = undefined;
        const props_hash_hex = try common.toHex(&props_hash, &hex_buf);
        std.log.info("Verification properties hash: {s}", .{props_hash_hex});

        // Setup TPM and store encryption keys, then write the corresponding
        // info to the verification config.
        try setupTpm(allocator, enc_roots, enc_roots_keys, mounts, props_hash, opts);
    } else {
        // Write verification config on disk with empty TPM info.
        try writeVerificationConfig(
            allocator,
            0,
            &[0]u8{},
            0,
            .{ .device = opts.tpm, .capabilities = tpm.Capabilities{} },
            opts.all_datasets,
            enc_roots_keys.items,
            mounts,
            opts.output,
        );
    }
}

fn setupTpm(
    allocator: std.mem.Allocator,
    enc_roots: std.StringHashMap([]const u8),
    enc_roots_keys: std.ArrayList([]const u8),
    mounts: std.StringHashMap([]const u8),
    props_hash: [DIGEST_SIZE]u8,
    opts: Options,
) !void {
    var enc_roots_values: std.ArrayList([]const u8) = try .initCapacity(allocator, enc_roots.count());
    defer enc_roots_values.deinit(allocator);
    var enc_roots_it = enc_roots.iterator();
    while (enc_roots_it.next()) |entry| {
        try enc_roots_values.append(allocator, entry.value_ptr.*);
    }

    const pcrs_indices: []const u8 = try getPcrsIndices(allocator, opts.measure);
    defer allocator.free(pcrs_indices);
    _ = std.mem.indexOfScalar(u8, pcrs_indices, opts.extend) orelse {
        std.log.err(
            "PCR {d} is not present in the list of measured PCRs {s}",
            .{ opts.extend, opts.measure },
        );
        return VelesError.IncorrectPcrs;
    };

    const serialized_pwds = try passwords.serializePasswords(allocator, enc_roots_values.items);
    defer allocator.free(serialized_pwds);
    defer std.crypto.secureZero(u8, @constCast(serialized_pwds));
    var tpm_dev = try tpm.Device.init(opts.tpm, null);
    defer tpm_dev.deinit();
    const handle = try tpm.setup(
        &tpm_dev,
        opts.slot,
        pcrs_indices,
        opts.extend,
        opts.force,
        serialized_pwds,
        &props_hash,
    );

    if (!opts.force) {
        // Verify we can unseal passwords.
        if (tpm.unseal(&tpm_dev, allocator, pcrs_indices, handle)) |unsealed_pwds| {
            std.crypto.secureZero(u8, @constCast(unsealed_pwds));
            allocator.free(unsealed_pwds);
        } else |err| {
            std.log.err("TPM unsealing check failed: {t}, exiting", .{err});
            std.process.exit(255);
        }

        // Make passwords unreadable from TPM.
        try tpm.extend(&tpm_dev, opts.extend, &.{});
    } else {
        std.log.err("Skipping TPM unsealing check because 'force' is set", .{});
    }

    // Write verification config on disk.
    try writeVerificationConfig(
        allocator,
        handle,
        pcrs_indices,
        opts.extend,
        .{ .device = opts.tpm, .capabilities = tpm_dev.caps },
        opts.all_datasets,
        enc_roots_keys.items,
        mounts,
        opts.output,
    );
}
