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

//! Hashes wrappers that perform dynamic dispatch based on
//! requested algorithm.

const std = @import("std");
const defs = @import("constants.zig");

const TpmError = defs.TpmError;

const Hasher = union(enum) {
    sha1: std.crypto.hash.Sha1,
    sha256: std.crypto.hash.sha2.Sha256,

    pub fn update(self: *Hasher, data: []const u8) void {
        switch (self.*) {
            inline else => |*impl| return impl.update(data),
        }
    }

    pub fn final(self: *Hasher, output: []u8) void {
        switch (self.*) {
            inline else => |*impl| return impl.final(output[0..@TypeOf(impl.*).digest_length]),
        }
    }

    pub fn size(self: Hasher) usize {
        switch (self) {
            inline else => |impl| return @TypeOf(impl).digest_length,
        }
    }
};

pub fn createHasher(hash_alg: u16) TpmError!Hasher {
    return switch (hash_alg) {
        defs.TPM_ALG_SHA1 => Hasher{ .sha1 = .init(.{}) },
        defs.TPM_ALG_SHA256 => Hasher{ .sha256 = .init(.{}) },
        else => TpmError.InternalError,
    };
}

const HmacHasher = union(enum) {
    sha1: std.crypto.auth.hmac.HmacSha1,
    sha256: std.crypto.auth.hmac.sha2.HmacSha256,

    pub fn update(self: *HmacHasher, data: []const u8) void {
        switch (self.*) {
            inline else => |*impl| return impl.update(data),
        }
    }

    pub fn final(self: *HmacHasher, output: []u8) void {
        switch (self.*) {
            inline else => |*impl| return impl.final(output[0..@TypeOf(impl.*).mac_length]),
        }
    }

    pub fn size(self: HmacHasher) usize {
        switch (self) {
            inline else => |impl| return @TypeOf(impl).mac_length,
        }
    }
};

pub fn createHmacHasher(hash_alg: u16, key: []const u8) TpmError!HmacHasher {
    return switch (hash_alg) {
        defs.TPM_ALG_SHA1 => HmacHasher{ .sha1 = .init(key) },
        defs.TPM_ALG_SHA256 => HmacHasher{ .sha256 = .init(key) },
        else => TpmError.InternalError,
    };
}

pub fn hash(hash_alg: u16, data: []const u8, output: []u8) TpmError!void {
    var hasher = try createHasher(hash_alg);
    hasher.update(data);
    hasher.final(output);
}
