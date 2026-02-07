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

//! Utility functions for working with Linux keyrings.

const std = @import("std");

const c = @cImport({
    @cInclude("keyutils.h");
});

const KeyUtilsError = error{
    CannotAddKey,
    CannotDeleteKey,
    KeyNotFound,
    PasswordTooLong,
};

pub fn getPasswordFromKeyring(keyname: [:0]const u8, password: []u8) ![]u8 {
    const key_id = c.request_key("user", keyname, null, c.KEY_SPEC_USER_KEYRING);
    if (key_id == -1) {
        std.log.err("Failed to find the password in keyring for '{s}'", .{keyname});
        return KeyUtilsError.KeyNotFound;
    }

    const key_size = c.keyctl_read(key_id, @ptrCast(password), password.len);
    if (key_size >= password.len) {
        std.log.err("Password size is too big: {d}", .{key_size});
        return KeyUtilsError.PasswordTooLong;
    }
    return password[0..@intCast(key_size)];
}

pub fn addPasswordToKeyring(keyname: [:0]const u8, password: []const u8) !void {
    const key_id = c.add_key("user", keyname, @ptrCast(password), password.len, c.KEY_SPEC_USER_KEYRING);
    if (key_id == -1) {
        std.log.err("Failed to add the password to keyring for '{s}'", .{keyname});
        return KeyUtilsError.CannotAddKey;
    }
}

pub fn deletePasswordFromKeyring(keyname: [:0]const u8) !void {
    const key_id = c.request_key("user", keyname, null, c.KEY_SPEC_USER_KEYRING);
    if (key_id == -1) {
        std.log.err("Failed to find the password in keyring for '{s}'", .{keyname});
        return KeyUtilsError.KeyNotFound;
    }

    if (c.keyctl_unlink(key_id, c.KEY_SPEC_USER_KEYRING) == -1) {
        std.log.err("Failed to unlink the password from keyring for '{s}'", .{keyname});
        return KeyUtilsError.CannotDeleteKey;
    }
}
