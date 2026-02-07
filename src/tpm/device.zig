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

//! TPM device interface.

const std = @import("std");

const buffer = @import("buffer.zig");
const capabilities = @import("commands/capabilities.zig");
const common = @import("../common.zig");
const defs = @import("constants.zig");
const hexdump = @import("../hexdump.zig").hexdump;

const TpmError = defs.TpmError;

pub const Device = struct {
    fd: std.posix.fd_t,
    pcr_hash_size: u16,
    hash_size: u16,
    entropy_size: u16,
    buf: buffer.Buffer,
    caps: defs.Capabilities,
    device_path: [256]u8 = undefined,

    const Self = @This();

    const RESPONSE_HEADER_SIZE: usize = 10;

    // Opens a connection to the TPM device at the specified path.
    pub fn init(device_path: []const u8, opt_caps: ?defs.Capabilities) TpmError!Self {
        // Need to convert slice to null-terminated string for open
        var path_buf: [256]u8 = undefined;
        if (device_path.len >= path_buf.len) {
            return TpmError.OpenFailed;
        }
        @memcpy(path_buf[0..device_path.len], device_path);
        path_buf[device_path.len] = 0;

        var stat: std.c.Stat = undefined;
        var fd: std.posix.fd_t = 0;
        if (std.c.stat(path_buf[0..device_path.len :0], &stat) != -1 and std.c.S.ISSOCK(stat.mode)) {
            const addr = try std.net.Address.initUnix(path_buf[0..device_path.len]);
            fd = std.c.socket(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0);
            if (fd == -1) {
                return TpmError.OpenFailed;
            }
            if (std.c.connect(fd, &addr.any, addr.getOsSockLen()) == -1) {
                return TpmError.OpenFailed;
            }
        } else {
            fd = try std.posix.open(
                path_buf[0..device_path.len :0],
                .{ .ACCMODE = .RDWR },
                0,
            );
        }
        var self = Self{
            .fd = fd,
            .buf = .init(),
            .pcr_hash_size = 0,
            .hash_size = 0,
            .entropy_size = 0,
            .caps = .{},
        };
        if (opt_caps) |caps| {
            self.caps = caps;
        } else {
            try capabilities.retrieveCapabilities(&self);
        }
        @memcpy(self.device_path[0..device_path.len], device_path);
        self.device_path[device_path.len] = 0;
        try capabilities.processCapabilities(&self);
        return self;
    }

    /// Closes the connection to the TPM device.
    pub fn deinit(self: *Self) void {
        std.posix.close(self.fd);
        self.fd = -1;
        self.buf.deinit();
    }

    pub fn sendReceive(self: *Self, exp_resp_size: ?u32) TpmError!void {
        // Which tag is in use?
        const write_tag = std.mem.readInt(u16, self.buf.buf[0..2], .big);
        // Fill in commandSize after we know packet size.
        std.mem.writeInt(u32, self.buf.buf[2..6], @intCast(self.buf.write_size), .big);

        if (common.debug) {
            var stdout_buffer: [common.BUFFER_SIZE]u8 = undefined;
            var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
            const stdout = &stdout_writer.interface;
            try hexdump(stdout, self.buf.buf[0..self.buf.write_size]);
        }

        _ = try std.posix.write(self.fd, self.buf.buf[0..self.buf.write_size]);

        self.buf.writeReset();

        const bytes_read = try std.posix.read(self.fd, &self.buf.buf);

        if (common.debug) {
            var stdout_buffer: [common.BUFFER_SIZE]u8 = undefined;
            var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
            const stdout = &stdout_writer.interface;
            try hexdump(stdout, self.buf.buf[0..bytes_read]);
        }

        if (bytes_read < RESPONSE_HEADER_SIZE) {
            return TpmError.ResponseTooShort;
        }

        self.buf.read_pos = 0;
        self.buf.read_size = @intCast(bytes_read);

        const tag = try self.buf.readInt(u16);
        const responseSize = try self.buf.readInt(u32);
        const responseCode = try self.buf.readInt(u32);

        if (tag != write_tag or responseCode != defs.TPM_RC_SUCCESS) {
            std.log.debug("TPM command failed: tag=0x{X}, code=0x{X}", .{ tag, responseCode });
            return TpmError.TpmCommandFailed;
        }

        if (bytes_read != responseSize) {
            std.log.err(
                "Unexpected TPM response: read {d} bytes but response size is {d} bytes",
                .{ bytes_read, responseSize },
            );
            return TpmError.InvalidResponse;
        }

        if (exp_resp_size != null and exp_resp_size.? != responseSize) {
            std.log.err(
                "Unexpected TPM response: response size is {d} bytes but expected {d} bytes",
                .{ responseSize, exp_resp_size.? },
            );
            return TpmError.InvalidResponse;
        }
    }
};
