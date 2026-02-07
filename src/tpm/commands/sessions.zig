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

//! TPM commands for working with sessions.

const std = @import("std");

const buffer = @import("../buffer.zig");
const common = @import("../../common.zig");
const data = @import("../data.zig");
const defs = @import("../constants.zig");
const device = @import("../device.zig");
const ecc_sessions = @import("ecc_sessions.zig");
const rsa_sessions = @import("rsa_sessions.zig");
const hashers = @import("../hashers.zig");

const TpmError = defs.TpmError;

pub fn startAuthSession(dev: *device.Device, is_trial: bool, entropy: []const u8) TpmError!u32 {
    const sessionType: u8 = if (is_trial) defs.TPM_SE_TRIAL else defs.TPM_SE_POLICY;

    try dev.buf.writeInt(u16, defs.TPM_ST_NO_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_StartAuthSession); // commandCode
    try dev.buf.writeInt(u32, defs.TPM_RH_NULL); // tpmKey
    try dev.buf.writeInt(u32, defs.TPM_RH_NULL); // bind
    try dev.buf.writeInt(u16, @intCast(entropy.len)); // nonceCaller:size
    try dev.buf.writeSlice(entropy); // nonceCaller: digest
    try dev.buf.writeInt(u16, 0); // encryptedSalt (empty buffer)
    try dev.buf.writeInt(u8, sessionType); // sessionType
    try dev.buf.writeInt(u16, defs.TPM_ALG_NULL); // symmetric
    try dev.buf.writeInt(u16, dev.caps.hash_alg); // authHash

    try dev.sendReceive(16 + dev.hash_size);

    return try dev.buf.readInt(u32); // sessionHandle
}

pub fn startSaltedAuthSession(
    dev: *device.Device,
    is_trial: bool,
    handle: u32,
    entropy: []const u8,
    salt: []const u8,
    nonce_tpm: []u8,
) TpmError!u32 {
    const sessionType: u8 = if (is_trial) defs.TPM_SE_TRIAL else defs.TPM_SE_POLICY;

    try dev.buf.writeInt(u16, defs.TPM_ST_NO_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_StartAuthSession); // commandCode
    try dev.buf.writeInt(u32, handle); // tpmKey
    try dev.buf.writeInt(u32, defs.TPM_RH_NULL); // bind
    try dev.buf.writeInt(u16, @intCast(entropy.len)); // nonceCaller:size
    try dev.buf.writeSlice(entropy); // nonceCaller: digest
    if (dev.caps.ecc_curve != 0) {
        try dev.buf.writeInt(u16, @intCast(2 * 2 + salt.len)); // encryptedSalt / size
        try dev.buf.writeInt(u16, @intCast(salt.len / 2)); // encryptedSalt / ECC point / x / size
        try dev.buf.writeSlice(salt[0 .. salt.len / 2]); // encryptedSalt / ECC point / x / data
        try dev.buf.writeInt(u16, @intCast(salt.len / 2)); // encryptedSalt / ECC point / y / size
        try dev.buf.writeSlice(salt[salt.len / 2 ..]); // encryptedSalt / ECC point / y / data
    } else {
        try dev.buf.writeInt(u16, @intCast(salt.len)); // encryptedSalt / size
        try dev.buf.writeSlice(salt); // encryptedSalt / rsa
    }
    try dev.buf.writeInt(u8, sessionType); // sessionType
    try dev.buf.writeInt(u16, defs.TPM_ALG_AES); // sym / algorithm
    try dev.buf.writeInt(u16, dev.caps.aes_key_bits); // sym / [algorithm]keyBits
    try dev.buf.writeInt(u16, defs.TPM_ALG_CFB); // sym / [algorithm]mode
    try dev.buf.writeInt(u16, dev.caps.hash_alg); // authHash

    try dev.sendReceive(16 + dev.hash_size);

    const session_handle = try dev.buf.readInt(u32); // sessionHandle
    try dev.buf.expectInt(u16, dev.hash_size); // nonceTPM / size
    try dev.buf.readIntoSlice(nonce_tpm);
    return session_handle;
}

pub fn policyGetDigest(dev: *device.Device, session_handle: u32, digest: []u8) TpmError!void {
    try dev.buf.writeInt(u16, defs.TPM_ST_NO_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_PolicyGetDigest); // commandCode
    try dev.buf.writeInt(u32, session_handle); // policySession

    try dev.sendReceive(12 + dev.hash_size);

    try dev.buf.expectInt(u16, dev.hash_size);
    try dev.buf.readIntoSlice(digest);
}

pub fn kdf_a(
    dev: *device.Device,
    key: []const u8,
    label: []const u8,
    context_u: []const u8,
    context_v: []const u8,
    size: u16,
    out: []u8,
) !void {
    var hasher = try hashers.createHasher(dev.caps.hash_alg);
    const hash_size = hasher.size();
    var buf: buffer.Buffer = .init();
    for (0..(size + hash_size - 1) / hash_size) |idx| {
        var hmac_hasher = try hashers.createHmacHasher(dev.caps.hash_alg, key);
        try buf.writeInt(u32, @intCast(idx + 1));
        try buf.writeSlice(label);
        try buf.writeSlice(context_u);
        try buf.writeSlice(context_v);
        try buf.writeInt(u32, size * 8);
        hmac_hasher.update(buf.buf[0..buf.write_pos]);
        hmac_hasher.final(buf.buf[buf.write_pos..][0..hash_size]);
        const rem_len = @min(size - idx * hash_size, hash_size);
        @memcpy(
            out[idx * hash_size .. idx * hash_size + rem_len],
            buf.buf[buf.write_pos..][0..rem_len],
        );
        buf.writeReset();
    }
}

pub fn kdf_e(
    dev: *device.Device,
    z: []const u8,
    label: []const u8,
    context_u: []const u8,
    context_v: []const u8,
    size: u16,
    out: []u8,
) !void {
    const hash_size = dev.hash_size;
    var buf: buffer.Buffer = .init();
    for (0..(size + hash_size - 1) / hash_size) |idx| {
        try buf.writeInt(u32, @intCast(idx + 1));
        try buf.writeSlice(z);
        try buf.writeSlice(label);
        try buf.writeSlice(context_u);
        try buf.writeSlice(context_v);
        var hasher = try hashers.createHasher(dev.caps.hash_alg);
        hasher.update(buf.buf[0..buf.write_pos]);
        hasher.final(buf.buf[buf.write_pos..][0..hash_size]);
        const rem_len = @min(size - idx * hash_size, hash_size);
        @memcpy(
            out[idx * hash_size .. idx * hash_size + rem_len],
            buf.buf[buf.write_pos..][0..rem_len],
        );
        buf.writeReset();
    }
}

pub fn getCpHash(dev: *device.Device, cmd: u32, name: []const u8, cp_hash: []u8) !void {
    var hasher = try hashers.createHasher(dev.caps.hash_alg);
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], cmd, .big);
    hasher.update(buf[0..4]);
    std.mem.writeInt(u16, buf[0..2], dev.caps.hash_alg, .big);
    hasher.update(buf[0..2]);
    hasher.update(name);
    hasher.final(cp_hash);
}

const AuthSession = union(enum) {
    rsa: rsa_sessions.RsaAuthSession,
    ecc: ecc_sessions.EccAuthSession,

    pub fn deinit(self: *AuthSession) void {
        switch (self.*) {
            inline else => |*impl| return impl.deinit(),
        }
    }

    pub fn getNonceTpm(self: *AuthSession) []u8 {
        switch (self.*) {
            inline else => |*impl| return impl.nonce_tpm.slice(),
        }
    }

    pub fn getPolicySessionHandle(self: *AuthSession) u32 {
        switch (self.*) {
            inline else => |*impl| return impl.policy_session_handle,
        }
    }

    pub fn getSessionKey(self: *AuthSession) []const u8 {
        switch (self.*) {
            inline else => |*impl| return impl.session_key.constSlice(),
        }
    }
};

pub fn createAuthSession(dev: *device.Device) TpmError!AuthSession {
    if (dev.caps.ecc_curve == 0) {
        return AuthSession{ .rsa = try .init(dev) };
    } else {
        return AuthSession{ .ecc = try .init(dev) };
    }
}
