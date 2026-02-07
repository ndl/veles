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

//! Functionality for interacting with ZFS filesystems.

const std = @import("std");
const eql = @import("std").mem.eql;

const set = @import("ziglangSet");

const common = @import("common.zig");
const passwords = @import("passwords.zig");

const BUFFER_SIZE = common.BUFFER_SIZE;
const DIGEST_SIZE = common.DIGEST_SIZE;

pub const Property = struct {
    value: []const u8,
    source: struct {
        type: []const u8,
        data: []const u8,
    },
};

pub const Dataset = struct {
    name: []const u8,
    type: []const u8,
    pool: []const u8,
    createtxg: []const u8,
    properties: std.json.ArrayHashMap(Property),
};

const Datasets = struct {
    output_version: struct {
        command: []const u8,
        vers_major: u32,
        vers_minor: u32,
    },
    datasets: std.json.ArrayHashMap(Dataset),
};

const ZfsError = error{
    CannotGetProperties,
    PasswordVerificationFailed,
};

pub fn getAllDatasetsProperties(allocator: std.mem.Allocator) !std.json.Parsed(Datasets) {
    // Gather all datasets and their properties.
    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "zfs", "get", "all", "-j" },
        .max_output_bytes = 1024 * 1024,
    });
    if (result.term.Exited != 0) {
        std.log.err("Failed to call 'zfs get': exit code {d}", .{result.term.Exited});
        return ZfsError.CannotGetProperties;
    }
    return std.json.parseFromSlice(Datasets, allocator, result.stdout, .{}) catch |err| {
        std.log.err("Failed to parse 'zfs get' output '{s}': {t}", .{ result.stdout, err });
        return err;
    };
}

pub fn getMounts(allocator: std.mem.Allocator, exclude: []const u8) !std.StringHashMap([]const u8) {
    var mounts: std.StringHashMap([]const u8) = .init(allocator);
    errdefer common.freeStringsMap(allocator, &mounts);
    var mounts_file = try std.fs.openFileAbsolute("/proc/mounts", .{});
    defer mounts_file.close();
    var mounts_buf: [BUFFER_SIZE]u8 = undefined;
    var mounts_reader: std.fs.File.Reader = mounts_file.reader(&mounts_buf);
    while (true) {
        if (mounts_reader.interface.takeDelimiterInclusive('\n')) |input| {
            var it = std.mem.splitScalar(u8, input, ' ');
            const name = it.next() orelse "";
            const path = it.next() orelse "";
            const fs = it.next() orelse "";
            if (eql(u8, fs, "zfs")) {
                if (isExcluded(exclude, name)) {
                    std.log.warn(
                        "Skipping ZFS dataset '{s}' at mount path '{s}' due to exclusion pattern",
                        .{ name, path },
                    );
                    continue;
                }
                std.log.debug("Storing ZFS dataset '{s}' at mount path '{s}'", .{ name, path });
                // Some datasets might be mounted multiple times, e.g. `/nix/store`.
                // Take only a single mount then.
                if (!mounts.contains(name)) {
                    try mounts.put(try allocator.dupe(u8, name), try allocator.dupe(u8, path));
                }
            }
        } else |err| {
            if (err == error.EndOfStream) break else return err;
        }
    }
    return mounts;
}

pub fn getTargetProperties(allocator: std.mem.Allocator) !set.Set([]const u8) {
    var target_props = set.Set([]const u8).init(allocator);
    _ = try target_props.appendSlice(&.{
        "canmount",
        "casesensitivity",
        "checksum",
        "createtxg",
        "encryption",
        "encryptionroot",
        "guid",
        "keyformat",
        "keylocation",
        "longname",
        "mountpoint",
        "normalization",
        "objsetid",
        "overlay",
        "pbkdf2iters",
        "type",
        "utf8only",
    });
    return target_props;
}

pub fn loadKey(
    allocator: std.mem.Allocator,
    ds_name: []const u8,
    password: []const u8,
    check_only: bool,
) !void {
    var child = std.process.Child.init(
        if (check_only)
            &([_][]const u8{ "zfs", "load-key", "-L", "prompt", "-n", ds_name })
        else
            &([_][]const u8{ "zfs", "load-key", "-L", "prompt", ds_name }),
        allocator,
    );
    child.stdin_behavior = std.process.Child.StdIo.Pipe;
    child.stdout_behavior = std.process.Child.StdIo.Pipe;
    child.stderr_behavior = std.process.Child.StdIo.Pipe;
    try child.spawn();
    if (child.stdin) |stdin| {
        _ = try stdin.write(password);
        stdin.close();
        child.stdin = null;
    } else {
        return ZfsError.PasswordVerificationFailed;
    }
    var stderr_buf: [BUFFER_SIZE]u8 = undefined;
    var err_msg: []const u8 = undefined;
    if (child.stderr) |stderr| {
        var stderr_reader = stderr.reader(&stderr_buf);
        if (stderr_reader.interface.takeDelimiterExclusive('\n')) |input| {
            err_msg = input;
        } else |err| {
            err_msg = @errorName(err);
        }
    }
    const term = try child.wait();
    if (term.Exited != 0) {
        std.log.err(
            "Key verification failed for dataset '{s}' with exit code {d}: '{s}'",
            .{ ds_name, term.Exited, err_msg },
        );
        return ZfsError.PasswordVerificationFailed;
    }
}

fn isExcluded(exclude: []const u8, name: []const u8) bool {
    if (exclude.len == 0) {
        return false;
    }
    var it = std.mem.splitScalar(u8, exclude, ',');
    while (it.next()) |pattern| {
        if (pattern.len == name.len and eql(u8, pattern, name[0..pattern.len])) {
            return true;
        }
    }
    return false;
}
