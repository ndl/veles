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

//! Functionality to securely query and store the passwords.

const std = @import("std");

const common = @import("common.zig");
const keyutils = @import("keyutils.zig");

const BUFFER_SIZE = common.BUFFER_SIZE;
const os = std.posix;
const io = std.io;

pub const PassphraseTooLong = error.PassphraseTooLong;
pub const PasswordPromptFailed = error.PasswordPromptFailed;

// This function is derived from
// https://github.com/enkore/zignify/blob/main/getpass.zig, ISC license
// *nix only
// OpenBSD has readpassphrase in libc.
// This is pretty much musl's getpass implementation.
pub fn getPasswordFromTerminal(
    comptime Checker: type,
    keyname: [:0]const u8,
    prompt: []const u8,
    buf: []u8,
    checker: Checker,
) ![]u8 {
    errdefer std.crypto.secureZero(u8, buf);
    if (@hasDecl(os.system, "termios")) {
        if (os.open("/dev/tty", .{ .ACCMODE = os.ACCMODE.RDWR, .NOCTTY = true }, 0)) |fd| {
            defer os.close(fd);

            const orig = try os.tcgetattr(fd);
            var no_echo = orig;
            // Don't echo.
            no_echo.lflag.ECHO = false;
            // Canonical mode: the terminal does line editing and only sends complete lines.
            no_echo.lflag.ICANON = true;
            // Translate carriage return to newline on input.
            no_echo.iflag.ICRNL = true;
            // Don't ignore carriage return on input.
            no_echo.iflag.IGNCR = false;
            // Don't translate NL to CR on input.
            no_echo.iflag.INLCR = false;

            try os.tcsetattr(fd, os.TCSA.FLUSH, no_echo);
            defer os.tcsetattr(fd, os.TCSA.FLUSH, orig) catch {};

            for (0..common.MAX_PASSWORD_TRIES) |_| {
                _ = try os.write(fd, prompt);
                const read = try os.read(fd, buf);
                _ = try os.write(fd, "\n");
                if (read == buf.len)
                    return PassphraseTooLong;
                if (read < 2) {
                    continue;
                }
                if (!checker.check(buf[0 .. read - 1])) {
                    continue;
                }
                try keyutils.addPasswordToKeyring(keyname, buf[0 .. read - 1]);
                return buf[0 .. read - 1];
            }
            return PasswordPromptFailed;
        } else |_| {}
    }
    // no tty, print prompt to stderr and read passphrase from stdin
    var err_buf: [BUFFER_SIZE]u8 = undefined;
    var stderr_writer = std.fs.File.stderr().writer(&err_buf);
    const stderr = &stderr_writer.interface;

    var stdin_reader = std.fs.File.stdin().reader(buf);
    const stdin = &stdin_reader.interface;

    for (0..common.MAX_PASSWORD_TRIES) |_| {
        try stderr.writeAll(prompt);
        if (stdin.takeDelimiterExclusive('\n')) |input| {
            if (input.len == buf.len)
                return PassphraseTooLong;
            if (!checker.check(input)) {
                continue;
            }
            try keyutils.addPasswordToKeyring(keyname, buf[0..input.len]);
            return input;
        } else |err| switch (err) {
            error.StreamTooLong => return PassphraseTooLong,
            else => return err,
        }
    }
    return PasswordPromptFailed;
}

pub fn getPasswordFromSystemd(
    comptime Checker: type,
    allocator: std.mem.Allocator,
    keyname: [:0]const u8,
    prompt: []const u8,
    buf: []u8,
    checker: Checker,
) ![]u8 {
    errdefer std.crypto.secureZero(u8, buf);
    const keyname_arg = try std.fmt.allocPrint(allocator, "--keyname={s}", .{keyname});
    defer allocator.free(keyname_arg);
    for (0..common.MAX_PASSWORD_TRIES) |_| {
        const result = try std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{
                "systemd-ask-password",
                keyname_arg,
                "--accept-cached",
                "--no-output",
                prompt,
            },
        });
        if (result.term.Exited != 0) {
            std.log.err(
                "Password prompt failed with exit code {d}",
                .{result.term.Exited},
            );
            continue;
        }
        const password = try keyutils.getPasswordFromKeyring(keyname, buf);
        if (!checker.check(password)) {
            continue;
        }
        return password;
    }
    return PasswordPromptFailed;
}

pub fn getPassword(
    comptime Checker: type,
    allocator: std.mem.Allocator,
    keyname: [:0]const u8,
    prompt: []const u8,
    buf: []u8,
    checker: Checker,
    systemd_ask_password: bool,
) ![]u8 {
    if (systemd_ask_password) {
        return try getPasswordFromSystemd(Checker, allocator, keyname, prompt, buf, checker);
    } else {
        return try getPasswordFromTerminal(Checker, keyname, prompt, buf, checker);
    }
}

pub fn serializePasswords(allocator: std.mem.Allocator, pwds: [][]const u8) ![]const u8 {
    return try std.mem.join(allocator, "\u{0000}", pwds);
}

pub fn deserializePasswords(allocator: std.mem.Allocator, serialized: []const u8) ![][]const u8 {
    var pwds: std.ArrayList([]const u8) = .empty;
    defer pwds.deinit(allocator);
    var it = std.mem.splitScalar(u8, serialized, 0);
    while (it.next()) |pwd| {
        try pwds.append(allocator, try allocator.dupe(u8, pwd));
    }
    return pwds.toOwnedSlice(allocator);
}
