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

//! High-level API for unsealing the passwords from TPM.

const std = @import("std");

const cfb = @import("cfb.zig").cfb;
const data = @import("data.zig");
const defs = @import("constants.zig");
const device = @import("device.zig");
const hashers = @import("hashers.zig");
const keys = @import("commands/keys.zig");
const pcrs = @import("commands/pcrs.zig");
const sessions = @import("commands/sessions.zig");

const TpmError = defs.TpmError;

pub fn unseal(
    dev: *device.Device,
    allocator: std.mem.Allocator,
    pcrs_indices: []const u8,
    persistent_handle: u32,
) TpmError![]const u8 {
    var auth_session = try sessions.createAuthSession(dev);
    defer auth_session.deinit();

    const nonce_tpm = auth_session.getNonceTpm();
    const policy_session_handle = auth_session.getPolicySessionHandle();
    const session_key = auth_session.getSessionKey();

    var init_auth_policy = try data.createHash(dev.caps.hash_alg);
    defer init_auth_policy.deinit();

    try sessions.policyGetDigest(dev, policy_session_handle, init_auth_policy.slice());

    try pcrs.policyPcr(dev, policy_session_handle, pcrs_indices, null);

    var auth_policy = try data.createHash(dev.caps.hash_alg);
    defer auth_policy.deinit();

    try sessions.policyGetDigest(dev, policy_session_handle, auth_policy.slice());

    var name = try data.createHash(dev.caps.hash_alg);
    defer name.deinit();

    try keys.readPublic(dev, persistent_handle, name.slice());

    var cp_hash = try data.createHash(dev.caps.hash_alg);
    defer cp_hash.deinit();

    try sessions.getCpHash(dev, defs.TPM_CC_Unseal, name.constSlice(), cp_hash.slice());

    var auth_hmac = try data.createHash(dev.caps.hash_alg);
    defer auth_hmac.deinit();

    var hasher = try hashers.createHmacHasher(dev.caps.hash_alg, session_key);
    hasher.update(cp_hash.constSlice());
    hasher.update(nonce_tpm);
    hasher.update(&[1]u8{defs.TPMA_SESSION_encrypt});
    hasher.final(auth_hmac.slice());

    const content = try keys.unseal(
        dev,
        allocator,
        policy_session_handle,
        persistent_handle,
        defs.TPMA_SESSION_encrypt,
        auth_hmac.constSlice(),
        nonce_tpm,
    );
    var key_iv = try data.createAesAndIV(dev.caps.aes_key_bits);
    const sym_key_size = dev.caps.aes_key_bits / 8;
    try sessions.kdf_a(
        dev,
        session_key,
        &defs.TPM_CFB_KEY,
        nonce_tpm,
        &[0]u8{},
        sym_key_size + defs.AES_IV_SIZE,
        key_iv.slice(),
    );

    switch (dev.caps.aes_key_bits) {
        128 => {
            const ctx = std.crypto.core.aes.Aes128.initEnc(key_iv.constSlice()[0..16].*);
            cfb(
                std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes128),
                ctx,
                content,
                content,
                key_iv.constSlice()[16..32].*,
            );
        },
        256 => {
            const ctx = std.crypto.core.aes.Aes256.initEnc(key_iv.constSlice()[0..32].*);
            cfb(
                std.crypto.core.aes.AesEncryptCtx(std.crypto.core.aes.Aes256),
                ctx,
                content,
                content,
                key_iv.constSlice()[32..48].*,
            );
        },
        else => return TpmError.NoSuitableParameters,
    }

    return content;
}
