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

//! Functionality for reading / writing TPM commands and responses.

const std = @import("std");
const common = @import("../common.zig");

pub const TpmError = error{
    ResponseTooShort,
    InvalidResponse,
    RequestIsTooLarge,
};

pub const Buffer = struct {
    read_pos: usize,
    read_size: usize,
    write_pos: usize,
    write_size: usize,
    buf: [common.BUFFER_SIZE]u8,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .read_pos = 0,
            .read_size = 0,
            .write_pos = 0,
            .write_size = 0,
            .buf = undefined,
        };
    }

    pub fn deinit(self: *Self) void {
        std.crypto.secureZero(u8, &self.buf);
    }

    fn readIntEndian(self: *Self, comptime T: type, endian: std.builtin.Endian) TpmError!T {
        const size = @typeInfo(T).int.bits / 8;
        if (self.read_pos + size > self.read_size) {
            return TpmError.ResponseTooShort;
        }
        const val: T = std.mem.readInt(T, self.buf[self.read_pos..][0..size], endian);
        self.read_pos += size;
        return val;
    }

    pub fn readInt(self: *Self, comptime T: type) TpmError!T {
        return self.readIntEndian(T, .big);
    }

    fn expectIntEndian(
        self: *Self,
        comptime T: type,
        expected: T,
        endian: std.builtin.Endian,
    ) TpmError!void {
        const val: T = try self.readIntEndian(T, endian);
        if (val != expected) {
            std.log.err("Unexpected response at pos {d}: 0x{X} != 0x{X}", .{ self.read_pos, val, expected });
            return TpmError.InvalidResponse;
        }
    }

    pub fn expectInt(self: *Self, comptime T: type, expected: T) TpmError!void {
        return self.expectIntEndian(T, expected, .big);
    }

    pub fn readSlice(self: *Self, size: usize) TpmError![]u8 {
        if (self.read_pos + size > self.read_size) {
            return TpmError.ResponseTooShort;
        }
        const result = self.buf[self.read_pos..][0..size];
        self.read_pos += size;
        return result;
    }

    pub fn readIntoSlice(self: *Self, out: []u8) TpmError!void {
        if (self.read_pos + out.len > self.read_size) {
            return TpmError.ResponseTooShort;
        }
        @memcpy(out, self.buf[self.read_pos..][0..out.len]);
        self.read_pos += out.len;
    }

    pub fn writeIntEndian(
        self: *Self,
        comptime T: type,
        value: T,
        endian: std.builtin.Endian,
    ) TpmError!void {
        const size = @typeInfo(T).int.bits / 8;
        if (self.write_pos + size > self.buf.len) {
            return TpmError.RequestIsTooLarge;
        }
        std.mem.writeInt(T, self.buf[self.write_pos..][0..size], value, endian);
        self.write_pos += size;
        self.write_size += size;
    }

    pub fn writeInt(self: *Self, comptime T: type, value: T) TpmError!void {
        return self.writeIntEndian(T, value, .big);
    }

    pub fn writeSlice(self: *Self, data: []const u8) TpmError!void {
        if (self.write_pos + data.len > self.buf.len) {
            return TpmError.RequestIsTooLarge;
        }
        @memcpy(self.buf[self.write_pos..][0..data.len], data);
        self.write_pos += data.len;
        self.write_size += data.len;
    }

    pub fn writeReset(self: *Self) void {
        self.write_pos = 0;
        self.write_size = 0;
    }
};
