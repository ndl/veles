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

//! Definitions and utility functions that are common for all
//! parts of the project.

const std = @import("std");

const tpm = @import("tpm.zig");

const c = @cImport({
    @cInclude("linux/fs.h");
    @cInclude("sys/ioctl.h");
});

pub var debug = false;

// SHA-256 settings. This is used for hashing ZFS-related stuff,
// is unrelated to the hash algorithm that TPM uses
// and can be changed independently.
pub const DIGEST_SIZE = 32; // in bytes
pub const Hasher = std.crypto.hash.sha2.Sha256;
pub const HmacHasher = std.crypto.auth.hmac.sha2.HmacSha256;

// Used in multiple places in the code as "big enough"
// value to hold temporary stuff like TPM requests / responses,
// hashes, etc - so be careful to not reduce it too much.
pub const BUFFER_SIZE = 1024;

// Max number of attempts to enter correct password.
pub const MAX_PASSWORD_TRIES = 3;

const POWER_OFF_DELAY_SECS = 10;
const ACTION_DELAY_SECS = 30;

pub const TpmInfo = struct {
    device: []const u8,
    capabilities: tpm.Capabilities,
};

// The config stored as part of 'setup' for subsequent use
// by 'load' and 'verify'.
pub const VerificationConfig = struct {
    slot: u32, // TPM persistent slot that we use for storing the passwords
    measure: []const u8, // TPM PCRs that are measured for passwords unsealing
    extend: u8, // TPM PCR that is extended as part of 'load' and 'verify'
    tpm: TpmInfo, // TPM info such as device path and discovered capabilities
    all_datasets: bool, // If true - verify properties for all datasets, not just mounted
    encryption_roots: [][]const u8, // List of all encryption roots we store passwords for
    mounts: [][2][]const u8, // List of all mounted ZFS datasets
};

pub fn toHex(data: []const u8, hex_buf: []u8) ![]const u8 {
    try std.crypto.codecs.hex.encode(
        hex_buf[0 .. 2 * data.len],
        data,
        std.fmt.Case.lower,
    );
    return hex_buf[0 .. 2 * data.len];
}

pub fn loadVerificationConfig(
    allocator: std.mem.Allocator,
    input_path: []const u8,
) !std.json.Parsed(VerificationConfig) {
    var config_file = std.fs.cwd().openFile(input_path, .{}) catch |err| {
        std.log.err("Failed to load Veles config '{s}': {t}", .{ input_path, err });
        return err;
    };
    defer config_file.close();
    var reader_buf: [BUFFER_SIZE]u8 = undefined;
    var reader = config_file.reader(&reader_buf);
    const reader_intf = &reader.interface;
    var json_reader: std.json.Reader = .init(allocator, reader_intf);
    const parsed_config = std.json.parseFromTokenSource(
        VerificationConfig,
        allocator,
        &json_reader,
        .{},
    ) catch |err| {
        std.log.err("Failed to parse Veles config '{s}': {t}", .{ input_path, err });
        return err;
    };
    return parsed_config;
}

fn tryExec(allocator: std.mem.Allocator, argv: []const []const u8) void {
    _ = std.process.Child.run(.{
        .allocator = allocator,
        .argv = argv,
    }) catch {};
}

pub fn poweroff(allocator: std.mem.Allocator, err: anyerror, is_load: bool) void {
    if (!is_load) {
        tryExec(allocator, &[_][]const u8{ "zfs", "umount", "-a" });
        tryExec(allocator, &[_][]const u8{ "umount", "-a" });
        tryExec(allocator, &[_][]const u8{ "zfs", "unload-key", "-a" });
    }
    std.log.err(
        "Validation failure, powering off the system in {d} seconds.",
        .{POWER_OFF_DELAY_SECS},
    );
    std.log.err("{t}", .{err});
    std.Thread.sleep(POWER_OFF_DELAY_SECS * 1000000000);
    std.posix.reboot(std.posix.RebootCommand.POWER_OFF) catch {
        std.log.err("Unable to power off, trying to reboot", .{});
        tryExec(allocator, &[_][]const u8{"reboot"});
        std.Thread.sleep(ACTION_DELAY_SECS * 1000000000);
        std.log.err("Unable to reboot normally, trying SysRq", .{});
        if (std.fs.openFileAbsolute("/proc/sysrq-trigger", .{})) |sysrq_file| {
            defer sysrq_file.close();
            sysrq_file.writeAll("s") catch {};
            sysrq_file.writeAll("u") catch {};
            sysrq_file.writeAll("b") catch {};
        } else |_| {}
    };
    std.Thread.sleep(ACTION_DELAY_SECS * 1000000000);
    std.log.err("All attempts at halting or rebooting failed, exiting", .{});
    std.posix.exit(255);
}

pub fn freeStringsMap(allocator: std.mem.Allocator, map: *std.StringHashMap([]const u8)) void {
    var it = map.*.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        allocator.free(entry.value_ptr.*);
    }
    map.*.deinit();
}

pub fn secureZeroStringsMap(map: *std.StringHashMap([]const u8)) void {
    var it = map.*.iterator();
    while (it.next()) |entry| {
        std.crypto.secureZero(u8, @constCast(entry.value_ptr.*));
    }
}

pub fn freeStringsArray(allocator: std.mem.Allocator, arr: *std.ArrayList([]const u8)) void {
    for (arr.items) |item| {
        allocator.free(item);
    }
    arr.*.deinit(allocator);
}

pub fn freeStringsSlice(allocator: std.mem.Allocator, slice: *[][]const u8) void {
    for (slice.*) |item| {
        allocator.free(@constCast(item));
    }
    allocator.free(slice.*);
}

pub fn secureZeroStringsSlice(items: [][]const u8) void {
    for (items) |item| {
        std.crypto.secureZero(u8, @constCast(item));
    }
}

// Sets 'immutable' flag on a file that prevents its removal by the standard file operations.
// This is needed for our verification hash files to make them more robust to accidental deletion
// and locking out the user out of their system due to boot verification failure.
pub fn setImmutable(file: std.fs.File) void {
    var attrs: u32 = 0;
    if (c.ioctl(file.handle, c.FS_IOC_GETFLAGS, &attrs) == -1) {
        std.log.err("Failed to get current attributes for the file: {t}", .{std.posix.errno(-1)});
    }
    attrs |= c.FS_IMMUTABLE_FL;
    if (c.ioctl(file.handle, c.FS_IOC_SETFLAGS, &attrs) == -1) {
        std.log.err("Failed to set new attributes for the file: {t}", .{std.posix.errno(-1)});
    }
}

// Clears 'immutable' flag on a file.
pub fn clearImmutable(file: std.fs.File) void {
    var attrs: u32 = 0;
    if (c.ioctl(file.handle, c.FS_IOC_GETFLAGS, &attrs) == -1) {
        std.log.err("Failed to get current attributes for the file: {t}", .{std.posix.errno(-1)});
    }
    attrs &= ~@as(u32, c.FS_IMMUTABLE_FL);
    if (c.ioctl(file.handle, c.FS_IOC_SETFLAGS, &attrs) == -1) {
        std.log.err("Failed to set new attributes for the file: {t}", .{std.posix.errno(-1)});
    }
}
