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

//! TPM commands for working with RSA-salted sessions.

const std = @import("std");

const data = @import("../data.zig");
const defs = @import("../constants.zig");
const device = @import("../device.zig");
const handles = @import("handles.zig");
const keys = @import("keys.zig");
const rsa = @import("rsa.zig");
const sessions = @import("sessions.zig");

const TpmError = defs.TpmError;

pub fn deriveRsaSessionKey(
    dev: *device.Device,
    salt: []const u8,
    nonce_caller: []const u8,
    nonce_tpm: []const u8,
    session_key: []u8,
) !void {
    try sessions.kdf_a(
        dev,
        salt,
        &defs.TPM_ATH_KEY,
        nonce_tpm,
        nonce_caller,
        dev.hash_size,
        session_key,
    );
}

pub const RsaAuthSession = struct {
    dev: *device.Device,
    nonce_tpm: data.Hash,
    policy_session_handle: u32,
    primary_handle: u32,
    session_key: data.Hash,

    const Self = @This();

    pub fn init(dev: *device.Device) TpmError!Self {
        var tpm_rsa_pub_key = try data.createRsaKey(dev.caps.rsa_key_bits);
        defer tpm_rsa_pub_key.deinit();

        // Do not initialize it with random bytes / use default zeros init,
        // as that's what default EK template expects.
        var primary_entropy = data.createEntropy(dev.entropy_size);
        defer primary_entropy.deinit();

        // Create RSA key in TPM and get its public data for encrypting the salt.
        // TPMs can generally take a long time to generate RSA keys, therefore
        // use EK template for generation - normally TPMs will do some optimizations
        // such as storing this key pre-generated to speed this case up, and we
        // don't really care that the key is the same on each run for our purposes
        // as we'll use it only to encrypt random salt in session setup.
        // Note that all the flags and values need to match exactly what TPM expects
        // for default EK template otherwise the optimized path won't be used.
        const primary_handle = try keys.createPrimary(
            dev,
            defs.TPMA_OBJECT_restricted |
                defs.TPMA_OBJECT_decrypt |
                defs.TPMA_OBJECT_adminWithPolicy,
            primary_entropy.constSlice(),
            &defs.TPM_IWG_EK_AUTH_POLICY,
            tpm_rsa_pub_key.slice(),
        );

        var salt = try data.createHash(dev.caps.hash_alg);
        defer salt.deinit();
        std.crypto.random.bytes(salt.slice());

        var encrypted_salt = try data.createRsaKey(dev.caps.rsa_key_bits);
        defer encrypted_salt.deinit();
        try rsa.encryptWithOaep(
            dev.caps.hash_alg,
            tpm_rsa_pub_key.constSlice(),
            salt.constSlice(),
            &defs.TPM_SECRET_KEY,
            encrypted_salt.slice(),
        );

        var session_entropy = try data.createHash(dev.caps.hash_alg);
        defer session_entropy.deinit();
        std.crypto.random.bytes(session_entropy.slice());

        var nonce_tpm = try data.createHash(dev.caps.hash_alg);
        defer nonce_tpm.deinit();

        const policy_session_handle = try sessions.startSaltedAuthSession(
            dev,
            false,
            primary_handle,
            session_entropy.constSlice(),
            encrypted_salt.constSlice(),
            nonce_tpm.slice(),
        );

        // Derive sessionKey as documented in
        // "Trusted Platform Module 2.0 Library Part 1: Architecture", "A.10.2" section.
        var session_key = try data.createHash(dev.caps.hash_alg);
        defer session_key.deinit();

        try deriveRsaSessionKey(
            dev,
            salt.constSlice(),
            session_entropy.constSlice(),
            nonce_tpm.slice(),
            session_key.slice(),
        );

        return Self{
            .dev = dev,
            .nonce_tpm = nonce_tpm,
            .policy_session_handle = policy_session_handle,
            .primary_handle = primary_handle,
            .session_key = session_key,
        };
    }

    pub fn deinit(self: *Self) void {
        self.nonce_tpm.deinit();
        self.session_key.deinit();
        handles.flushContext(self.dev, self.primary_handle) catch {};
    }
};
