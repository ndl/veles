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

//! Functionality for authenticating ZFS datasets.

const std = @import("std");
const eql = @import("std").mem.eql;

const set = @import("ziglangSet");

const common = @import("common.zig");
const passwords = @import("passwords.zig");
const properties = @import("properties.zig");
const zfs = @import("zfs.zig");

const BUFFER_SIZE = common.BUFFER_SIZE;
const DIGEST_SIZE = common.DIGEST_SIZE;

const DatasetError = error{
    HashReadFailed,
    HashVerificationFailed,
    HashWriteFailed,
    MissingEncryptionRoot,
    UnsupportedKeyFormat,
};

pub fn verifyMetadataForDataset(
    allocator: std.mem.Allocator,
    enc_root: []const u8,
    ds_name: []const u8,
    mount_path: []const u8,
    password: []const u8,
    props: std.StringArrayHashMapUnmanaged(zfs.Property),
    target_props: set.Set([]const u8),
    pwd_hashes_to_enc_roots: *std.StringHashMap([]const u8),
) ![]const u8 {
    const meta = try readMetadataForDataset(allocator, mount_path);
    errdefer allocator.free(meta);
    const actual_props_hash = meta[0..DIGEST_SIZE];
    const actual_pwd_hash = meta[DIGEST_SIZE..];
    const expected_props_hash = try getPropertiesHashForDataset(
        allocator,
        ds_name,
        props,
        target_props,
    );
    if (!eql(u8, &expected_props_hash, actual_props_hash)) {
        std.log.debug("Properties verification failed for dataset '{s}'", .{ds_name});
        return DatasetError.HashVerificationFailed;
    }
    const other_enc_root = pwd_hashes_to_enc_roots.get(actual_pwd_hash);
    if (other_enc_root != null) {
        std.log.debug(
            "Password hash for dataset at '{s}' has matching encryption root '{s}'",
            .{ mount_path, other_enc_root.? },
        );
        if (!eql(u8, enc_root, other_enc_root.?)) {
            std.log.debug("Encryption root verification failed for dataset '{s}'", .{ds_name});
            return DatasetError.HashVerificationFailed;
        }
    } else {
        std.log.debug("Password hash for dataset at '{s}' was not seen yet, verifying", .{mount_path});
        try verifyPasswordHashForDataset(allocator, actual_pwd_hash, password);
        try pwd_hashes_to_enc_roots.put(
            try allocator.dupe(u8, actual_pwd_hash),
            try allocator.dupe(u8, enc_root),
        );
    }
    return meta;
}

pub fn writeMetadataForAllDatasets(
    allocator: std.mem.Allocator,
    datasets: std.StringArrayHashMapUnmanaged(zfs.Dataset),
    mounts: std.StringHashMap([]const u8),
    kdf_params: std.crypto.pwhash.argon2.Params,
    systemd_ask_password: bool,
) !std.StringHashMap([]const u8) {
    // For each encryption root store its password.
    var enc_roots_to_pwds = std.StringHashMap([]const u8).init(allocator);
    errdefer common.freeStringsMap(allocator, &enc_roots_to_pwds);
    errdefer common.secureZeroStringsMap(&enc_roots_to_pwds);

    // For each encryption root store its password hash (either newly computed or
    // read from disk) and reuse for other datasets with the same encryption root.
    var enc_roots_to_pwd_hashes = std.StringHashMap([]const u8).init(allocator);
    defer common.freeStringsMap(allocator, &enc_roots_to_pwd_hashes);
    defer common.secureZeroStringsMap(&enc_roots_to_pwd_hashes);

    // ZFS properties to hash.
    var target_props = try zfs.getTargetProperties(allocator);
    defer target_props.deinit();

    var ds_it = datasets.iterator();
    while (ds_it.next()) |ds| {
        const ds_name = ds.key_ptr.*;
        const mount_path = mounts.get(ds_name) orelse {
            std.log.warn("Skipping dataset '{s}' because it is not mounted", .{ds_name});
            continue;
        };
        const props = ds.value_ptr.properties.map;
        if (eql(u8, if (props.get("encryption")) |v| v.value else "off", "off")) {
            continue;
        }
        if (!eql(u8, if (props.get("keyformat")) |v| v.value else "", "passphrase")) {
            std.log.err("Failed to parse 'keyformat' for dataset '{s}'", .{ds_name});
            return DatasetError.UnsupportedKeyFormat;
        }
        if (props.get("encryptionroot")) |v| {
            const enc_root = v.value;
            // Ask for password for this encryption root, if it's not available yet.
            if (!enc_roots_to_pwds.contains(enc_root)) {
                try enc_roots_to_pwds.put(
                    try allocator.dupe(u8, enc_root),
                    try askPassword(allocator, enc_root, systemd_ask_password),
                );
            }
            const password = enc_roots_to_pwds.get(enc_root).?;
            const expected_props_hash = try getPropertiesHashForDataset(
                allocator,
                ds_name,
                props,
                target_props,
            );
            const actual_metadata = readMetadataForDataset(allocator, mount_path) catch null;
            defer {
                if (actual_metadata != null) allocator.free(actual_metadata.?);
            }
            try writeMetadataForDataset(
                allocator,
                enc_root,
                ds_name,
                mount_path,
                password,
                kdf_params,
                &expected_props_hash,
                actual_metadata,
                &enc_roots_to_pwd_hashes,
            );
        } else {
            std.log.err("Missing 'encryptionroot' for encrypted dataset '{s}'", .{ds_name});
            return DatasetError.MissingEncryptionRoot;
        }
    }
    return enc_roots_to_pwds;
}

fn askPassword(
    allocator: std.mem.Allocator,
    ds_name: []const u8,
    systemd_ask_password: bool,
) ![]const u8 {
    var password_buf: [BUFFER_SIZE]u8 = undefined;
    defer std.crypto.secureZero(u8, &password_buf);
    const prompt = try std.fmt.allocPrint(
        allocator,
        "Enter password for encryption root '{s}':",
        .{ds_name},
    );
    defer allocator.free(prompt);
    const keyname = try std.fmt.allocPrintSentinel(
        allocator,
        "zfs-{s}",
        .{ds_name},
        0,
    );
    defer allocator.free(keyname);
    var password: []u8 = undefined;
    const Checker = struct {
        allocator: std.mem.Allocator,
        enc_root: []const u8,
        pub fn check(self: *const @This(), pwd: []const u8) bool {
            zfs.loadKey(self.allocator, self.enc_root, pwd, true) catch |err| {
                std.log.err(
                    "Failed loading the key for encryption root '{s}': {t}",
                    .{ self.enc_root, err },
                );
                return false;
            };
            return true;
        }
    };
    const checker: Checker = .{ .allocator = allocator, .enc_root = ds_name };
    password = try passwords.getPassword(
        Checker,
        allocator,
        keyname,
        prompt,
        &password_buf,
        checker,
        systemd_ask_password,
    );
    return try allocator.dupe(u8, password);
}

fn getDatasetMetadataPath(allocator: std.mem.Allocator, mount_path: []const u8) ![]const u8 {
    return try std.fmt.allocPrint(
        allocator,
        "{s}/.veles.metadata",
        .{if (eql(u8, mount_path, "/")) "" else mount_path},
    );
}

fn getPropertiesHashForDataset(
    allocator: std.mem.Allocator,
    ds_name: []const u8,
    props: std.StringArrayHashMapUnmanaged(zfs.Property),
    target_props: set.Set([]const u8),
) ![DIGEST_SIZE]u8 {
    var props_to_hash: std.ArrayList([]const u8) = .empty;
    defer common.freeStringsArray(allocator, &props_to_hash);
    try properties.appendTargetProperties(
        allocator,
        ds_name,
        props,
        target_props,
        &props_to_hash,
    );

    var props_hasher = common.Hasher.init(.{});
    for (props_to_hash.items) |item| {
        props_hasher.update(item);
        props_hasher.update("\n");
    }
    var props_hash: [DIGEST_SIZE]u8 = undefined;
    props_hasher.final(&props_hash);
    return props_hash;
}

fn readMetadataForDataset(allocator: std.mem.Allocator, mount_path: []const u8) ![]const u8 {
    const meta_path = try getDatasetMetadataPath(allocator, mount_path);
    defer allocator.free(meta_path);
    var meta_file = try std.fs.openFileAbsolute(meta_path, .{});
    defer meta_file.close();
    var metadata: [BUFFER_SIZE]u8 = undefined;
    const meta_size = try meta_file.readAll(&metadata);
    if (meta_size <= DIGEST_SIZE) {
        return DatasetError.HashReadFailed;
    } else {
        return try allocator.dupe(u8, metadata[0..meta_size]);
    }
}

fn resetImmutable(output_path: []const u8) !void {
    var file = std.fs.cwd().openFile(output_path, .{}) catch |err| {
        std.log.debug(
            "Couldn't open '{s}': {t}, assume it doesn't exist",
            .{ output_path, err },
        );
        return;
    };
    defer file.close();
    common.clearImmutable(file);
}

fn verifyPasswordHashForDataset(
    allocator: std.mem.Allocator,
    pwd_hash: []const u8,
    password: []const u8,
) !void {
    std.crypto.pwhash.argon2.strVerify(
        pwd_hash,
        password,
        .{ .allocator = allocator },
    ) catch {
        return DatasetError.HashVerificationFailed;
    };
}

fn writeMetadataForDataset(
    allocator: std.mem.Allocator,
    enc_root: []const u8,
    ds_name: []const u8,
    mount_path: []const u8,
    password: []const u8,
    kdf_params: std.crypto.pwhash.argon2.Params,
    expected_props_hash: []const u8,
    actual_metadata: ?[]const u8,
    enc_roots_to_pwd_hashes: *std.StringHashMap([]const u8),
) !void {
    var expected_pwd_hash = enc_roots_to_pwd_hashes.get(enc_root);

    const actual_props_hash = if (actual_metadata != null) actual_metadata.?[0..DIGEST_SIZE] else null;
    const actual_pwd_hash = if (actual_metadata != null) actual_metadata.?[DIGEST_SIZE..] else null;

    // Do we know the hash for this encryption root already?
    if (expected_pwd_hash != null) {
        if (actual_props_hash != null and
            eql(u8, expected_props_hash, actual_props_hash.?) and
            actual_pwd_hash != null and
            eql(u8, expected_pwd_hash.?, actual_pwd_hash.?))
        {
            std.log.info(
                "Dataset '{s}' has matching verification metadata already",
                .{ds_name},
            );
            return;
        }
    }

    // It's possible that that actual password hash on disk is valid, just
    // different from what we have.
    if (actual_pwd_hash != null) {
        if (verifyPasswordHashForDataset(
            allocator,
            actual_pwd_hash.?,
            password,
        )) |_| {
            if (expected_pwd_hash == null) {
                try enc_roots_to_pwd_hashes.put(
                    try allocator.dupe(u8, enc_root),
                    try allocator.dupe(u8, actual_pwd_hash.?),
                );
            }
            if (actual_props_hash != null and eql(u8, expected_props_hash, actual_props_hash.?)) {
                std.log.info(
                    "Dataset '{s}' has matching verification metadata already",
                    .{ds_name},
                );
                return;
            }
        } else |err| {
            std.log.warn(
                "Password hash for dataset '{s}' doesn't verify ({t}), re-creating",
                .{ ds_name, err },
            );
        }
    }

    // Compute the password hash if we don't know it yet.
    if (expected_pwd_hash == null) {
        std.log.info("Computing new password hash for dataset '{s}'", .{ds_name});
        var buf: [BUFFER_SIZE]u8 = undefined;
        expected_pwd_hash = try std.crypto.pwhash.argon2.strHash(
            password,
            .{
                .allocator = allocator,
                .params = kdf_params,
            },
            &buf,
        );
        try enc_roots_to_pwd_hashes.put(
            try allocator.dupe(u8, enc_root),
            try allocator.dupe(u8, expected_pwd_hash.?),
        );
    } else {
        std.log.info("Reusing existing password hash for dataset '{s}'", .{ds_name});
    }

    var meta_buf: [BUFFER_SIZE]u8 = undefined;
    const meta = meta_buf[0 .. DIGEST_SIZE + expected_pwd_hash.?.len];
    @memcpy(meta_buf[0..DIGEST_SIZE], expected_props_hash);
    @memcpy(meta_buf[DIGEST_SIZE..meta.len], expected_pwd_hash.?);

    // Convert to hex.
    var meta_buf_hex: [BUFFER_SIZE]u8 = undefined;
    const meta_hex = try common.toHex(expected_pwd_hash.?, &meta_buf_hex);
    const meta_path = try getDatasetMetadataPath(allocator, mount_path);
    defer allocator.free(meta_path);
    std.log.info("Writing metadata {s} to {s}", .{ meta_hex, meta_path });

    try resetImmutable(meta_path);
    var meta_file = std.fs.createFileAbsolute(meta_path, .{ .mode = 0o0600 }) catch |err| {
        std.log.err("Failed to open file '{s}' for writing: {t}", .{ meta_path, err });
        return DatasetError.HashWriteFailed;
    };
    defer meta_file.close();
    try meta_file.writeAll(meta);
    common.setImmutable(meta_file);
}
