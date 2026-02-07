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

//! TPM commands for working with ECC-salted sessions.

const std = @import("std");

const data = @import("../data.zig");
const defs = @import("../constants.zig");
const device = @import("../device.zig");
const handles = @import("handles.zig");
const keys = @import("keys.zig");
const sessions = @import("sessions.zig");

const TpmError = defs.TpmError;

pub fn getEccSharedSecret(
    ecc_curve: u16,
    tpm_ecc_point_x: []const u8,
    tpm_ecc_point_y: []const u8,
    our_ecc_point_x: []u8,
    our_ecc_point_y: []u8,
    shared_secret: []u8,
) TpmError!void {
    switch (ecc_curve) {
        defs.TPM_ECC_NIST_P256 => {
            getEccSharedSecretImpl(
                std.crypto.ecc.P256,
                tpm_ecc_point_x,
                tpm_ecc_point_y,
                our_ecc_point_x,
                our_ecc_point_y,
                shared_secret,
            ) catch return TpmError.EccOperationError;
        },
        defs.TPM_ECC_NIST_P384 => {
            getEccSharedSecretImpl(
                std.crypto.ecc.P384,
                tpm_ecc_point_x,
                tpm_ecc_point_y,
                our_ecc_point_x,
                our_ecc_point_y,
                shared_secret,
            ) catch return TpmError.EccOperationError;
        },
        else => {
            return TpmError.NoSuitableParameters;
        },
    }
}

fn getEccSharedSecretImpl(
    comptime EccPoint: type,
    tpm_ecc_point_x: []const u8,
    tpm_ecc_point_y: []const u8,
    our_ecc_point_x: []u8,
    our_ecc_point_y: []u8,
    shared_secret: []u8,
) !void {
    const ecc_key_size = comptime EccPoint.Fe.encoded_length;
    // Create our own private ECC key and get corresponding public ECC point for ECDH.
    const d = EccPoint.scalar.random(.little);
    const our_ecc_pnt = (try EccPoint.basePoint.mul(d, .little)).affineCoordinates();
    @memcpy(our_ecc_point_x[0..ecc_key_size], &our_ecc_pnt.x.toBytes(.big));
    @memcpy(our_ecc_point_y[0..ecc_key_size], &our_ecc_pnt.y.toBytes(.big));
    var tpm_ecc_pnt: EccPoint = try .fromSerializedAffineCoordinates(
        tpm_ecc_point_x[0..ecc_key_size].*,
        tpm_ecc_point_y[0..ecc_key_size].*,
        .big,
    );
    const z = (try tpm_ecc_pnt.mul(d, .little)).affineCoordinates();
    @memcpy(shared_secret, &z.x.toBytes(.big));
}

pub fn deriveEccSessionKey(
    dev: *device.Device,
    tpm_ecc_point_x: []const u8,
    our_ecc_point_x: []const u8,
    shared_secret: []const u8,
    nonce_caller: []const u8,
    nonce_tpm: []const u8,
    session_key: []u8,
) !void {
    var salt = try data.createHash(dev.caps.hash_alg);
    defer salt.deinit();

    try sessions.kdf_e(
        dev,
        shared_secret,
        &defs.TPM_SECRET_KEY,
        our_ecc_point_x,
        tpm_ecc_point_x,
        dev.hash_size,
        salt.slice(),
    );

    try sessions.kdf_a(
        dev,
        salt.constSlice(),
        &defs.TPM_ATH_KEY,
        nonce_tpm,
        nonce_caller,
        dev.hash_size,
        session_key,
    );
}

pub const EccAuthSession = struct {
    dev: *device.Device,
    nonce_tpm: data.Hash,
    policy_session_handle: u32,
    primary_handle: u32,
    session_key: data.Hash,

    const Self = @This();

    pub fn init(dev: *device.Device) TpmError!Self {
        var tpm_ecc_point_x = try data.createEccCoord(dev.caps.ecc_curve);
        defer tpm_ecc_point_x.deinit();

        var tpm_ecc_point_y = try data.createEccCoord(dev.caps.ecc_curve);
        defer tpm_ecc_point_y.deinit();

        var primary_entropy = data.createEntropy(dev.entropy_size);
        defer primary_entropy.deinit();
        std.crypto.random.bytes(primary_entropy.slice());

        // Create ECC key in TPM and get its ECC point for ECDH.
        // Generating ECC keys is cheap and we don't need TPM attestation
        // in our use case => creating ephemeral key is fine.
        var pub_data = try data.createEccPoint(dev.caps.ecc_curve);
        const primary_handle = try keys.createPrimary(
            dev,
            defs.TPMA_OBJECT_restricted |
                defs.TPMA_OBJECT_decrypt |
                defs.TPMA_OBJECT_adminWithPolicy,
            primary_entropy.constSlice(),
            &[0]u8{},
            pub_data.slice(),
        );
        const ecc_coord_size = tpm_ecc_point_x.size;
        @memcpy(tpm_ecc_point_x.slice(), pub_data.constSlice()[0..ecc_coord_size]);
        @memcpy(tpm_ecc_point_y.slice(), pub_data.constSlice()[ecc_coord_size..]);

        var our_ecc_point_x = try data.createEccCoord(dev.caps.ecc_curve);
        defer our_ecc_point_x.deinit();

        var our_ecc_point_y = try data.createEccCoord(dev.caps.ecc_curve);
        defer our_ecc_point_y.deinit();

        var shared_secret = try data.createEccCoord(dev.caps.ecc_curve);
        defer shared_secret.deinit();

        try getEccSharedSecret(
            dev.caps.ecc_curve,
            tpm_ecc_point_x.constSlice(),
            tpm_ecc_point_y.constSlice(),
            our_ecc_point_x.slice(),
            our_ecc_point_y.slice(),
            shared_secret.slice(),
        );

        var session_entropy = try data.createHash(dev.caps.hash_alg);
        defer session_entropy.deinit();
        std.crypto.random.bytes(session_entropy.slice());

        var nonce_tpm = try data.createHash(dev.caps.hash_alg);
        defer nonce_tpm.deinit();

        @memcpy(pub_data.slice()[0..ecc_coord_size], our_ecc_point_x.constSlice());
        @memcpy(pub_data.slice()[ecc_coord_size..], our_ecc_point_y.constSlice());
        const policy_session_handle = try sessions.startSaltedAuthSession(
            dev,
            false,
            primary_handle,
            session_entropy.constSlice(),
            pub_data.constSlice(),
            nonce_tpm.slice(),
        );

        // Derive sessionKey as documented in
        // "Trusted Platform Module 2.0 Library Part 1: Architecture", "B.6.1" section.
        var session_key = try data.createHash(dev.caps.hash_alg);
        defer session_key.deinit();

        try deriveEccSessionKey(
            dev,
            tpm_ecc_point_x.constSlice(),
            our_ecc_point_x.constSlice(),
            shared_secret.constSlice(),
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
