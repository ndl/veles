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

//! Functionality for computing ZFS properties verification hashes.

const std = @import("std");
const eql = @import("std").mem.eql;

const set = @import("ziglangSet");

const common = @import("common.zig");
const zfs = @import("zfs.zig");

const DIGEST_SIZE = common.DIGEST_SIZE;

const PropertiesError = error{
    MissingProperties,
};

pub fn appendTargetProperties(
    allocator: std.mem.Allocator,
    ds_name: []const u8,
    props: std.StringArrayHashMapUnmanaged(zfs.Property),
    target_props: set.Set([]const u8),
    out_props: *std.ArrayList([]const u8),
) !void {
    var prop_it = props.iterator();
    while (prop_it.next()) |prop_entry| {
        const prop_name = prop_entry.key_ptr.*;
        if (target_props.contains(prop_name)) {
            const prop_value = prop_entry.value_ptr.*.value;
            const prop_line = try std.fmt.allocPrint(
                allocator,
                "{s}:{s}:{s}",
                .{ ds_name, prop_name, prop_value },
            );
            try out_props.append(allocator, prop_line);
        }
    }
}

pub fn getPropertiesHashForAllDatasets(
    allocator: std.mem.Allocator,
    datasets: std.StringArrayHashMapUnmanaged(zfs.Dataset),
    all_datasets: bool,
    mounts: std.StringHashMap([]const u8),
) ![DIGEST_SIZE]u8 {
    var target_props = try zfs.getTargetProperties(allocator);
    defer target_props.deinit();

    // Sanity check: all mounts should have datasets properties.
    try checkAllMountsHaveProperties(datasets, mounts);

    // Create sorted properties for all datasets so that we can hash them.
    var ds_it = datasets.iterator();
    var props_to_hash: std.ArrayList([]const u8) = .empty;
    defer common.freeStringsArray(allocator, &props_to_hash);
    while (ds_it.next()) |ds_entry| {
        const ds_name = ds_entry.key_ptr.*;
        if (!all_datasets and mounts.get(ds_name) == null) {
            std.log.warn(
                "Dataset '{s}' is not mounted, skipping for properties verification",
                .{ds_name},
            );
            continue;
        }
        try appendTargetProperties(
            allocator,
            ds_name,
            ds_entry.value_ptr.properties.map,
            target_props,
            &props_to_hash,
        );
    }
    std.mem.sort([]const u8, props_to_hash.items, {}, stringLessThan);
    if (common.debug) {
        std.log.debug("Properties that will be hashed:", .{});
        for (props_to_hash.items) |item| {
            std.log.debug("{s}", .{item});
        }
    }
    var props_hasher = common.Hasher.init(.{});
    for (props_to_hash.items) |item| {
        props_hasher.update(item);
        props_hasher.update("\n");
    }
    var props_hash: [DIGEST_SIZE]u8 = undefined;
    props_hasher.final(&props_hash);
    return props_hash;
}

fn checkAllMountsHaveProperties(
    datasets: std.StringArrayHashMapUnmanaged(zfs.Dataset),
    mounts: std.StringHashMap([]const u8),
) !void {
    var mount_it = mounts.iterator();
    while (mount_it.next()) |mount_entry| {
        const ds_name = mount_entry.key_ptr.*;
        if (datasets.get(ds_name) == null) {
            std.log.err("Couldn't find properties for ZFS dataset '{s}'", .{ds_name});
            return PropertiesError.MissingProperties;
        }
    }
}

fn getPropertiesHashForDataset(
    allocator: std.mem.Allocator,
    ds_name: []const u8,
    props: std.StringArrayHashMapUnmanaged(zfs.Property),
    target_props: set.Set([]const u8),
) ![DIGEST_SIZE]u8 {
    var props_to_hash: std.ArrayList([]const u8) = .empty;
    defer common.freeStringsArray(allocator, &props_to_hash);
    try appendTargetProperties(
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

fn stringLessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.order(u8, lhs, rhs) == .lt;
}
