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

//! TPM commands for operations on keys.

const std = @import("std");

const auth = @import("auth.zig");
const common = @import("../../common.zig");
const defs = @import("../constants.zig");
const device = @import("../device.zig");

const TpmError = defs.TpmError;

pub fn createPrimary(
    dev: *device.Device,
    extra_flags: u32,
    entropy: []const u8,
    auth_policy: []const u8,
    pub_data: ?[]u8,
) TpmError!u32 {
    try dev.buf.writeInt(u16, defs.TPM_ST_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_CreatePrimary); // commandCode
    try dev.buf.writeInt(u32, defs.TPM_RH_ENDORSEMENT); // primaryHandle
    try auth.writeAuthCommand(dev, defs.TPM_RS_PW);
    try dev.buf.writeInt(u16, 4); // inSensitive: size
    try dev.buf.writeInt(u16, 0); // userAuth: size
    try dev.buf.writeInt(u16, 0); // sensitiveData: size
    try dev.buf.writeInt(u16, @intCast(26 + auth_policy.len + entropy.len)); // inPublic / size
    if (dev.caps.ecc_curve != 0) {
        try dev.buf.writeInt(u16, defs.TPM_ALG_ECC); // inPublic / publicArea / type
    } else {
        try dev.buf.writeInt(u16, defs.TPM_ALG_RSA); // inPublic / publicArea / type
    }
    try dev.buf.writeInt(u16, dev.caps.hash_alg); // inPublic / publicArea / nameAlg
    try dev.buf.writeInt(
        u32,
        defs.TPMA_OBJECT_fixedTPM |
            defs.TPMA_OBJECT_fixedParent |
            defs.TPMA_OBJECT_sensitiveDataOrigin |
            extra_flags,
    ); // inPublic / publicArea / objectAttributes
    try dev.buf.writeInt(u16, @intCast(auth_policy.len)); // inPublic / publicArea / authPolicy / size
    try dev.buf.writeSlice(auth_policy); // inPublic / publicArea / authPolicy / data
    try dev.buf.writeInt(u16, defs.TPM_ALG_AES); // inPublic / publicArea / [type]parameters / rsaDetail | eccDetail / symmetric / algorithm
    try dev.buf.writeInt(u16, dev.caps.aes_key_bits); // inPublic /publicArea / [type]parameters / rsaDetail | eccDetail / symmetric / keyBits
    try dev.buf.writeInt(u16, defs.TPM_ALG_CFB); // inPublic /publicArea / [type]parameters / rsaDetail | eccDetail / symmetric / mode
    try dev.buf.writeInt(u16, defs.TPM_ALG_NULL); // inPublic /publicArea / [type]parameters / rsaDetail | eccDetail / scheme
    if (dev.caps.ecc_curve != 0) {
        try dev.buf.writeInt(u16, dev.caps.ecc_curve); // inPublic / publicArea / [type]parameters / eccDetail / curveID
        try dev.buf.writeInt(u16, defs.TPM_ALG_NULL); // inPublic /publicArea / [type]parameters / eccDetail / kdf
        const half_entropy_size: u16 = @intCast(entropy.len / 2);
        try dev.buf.writeInt(u16, half_entropy_size); // inPublic / unique / ecc / x / size
        try dev.buf.writeSlice(entropy[0..half_entropy_size]); // inPublic / unique / ecc / x / data
        try dev.buf.writeInt(u16, half_entropy_size); // inPublic / unique / ecc / y / size
        try dev.buf.writeSlice(entropy[half_entropy_size .. 2 * half_entropy_size]); // inPublic / unique / ecc / y / data
    } else {
        try dev.buf.writeInt(u16, dev.caps.rsa_key_bits); // inPublic /publicArea / [typeParameters] / rsaDetail / keyBits
        try dev.buf.writeInt(u32, defs.RSA_PUB_EXP); // inPublic /publicArea / [typeParameters] / rsaDetail / exponent
        try dev.buf.writeInt(u16, @intCast(entropy.len)); // inPublic / unique / rsa / size
        try dev.buf.writeSlice(entropy);
    }
    try dev.buf.writeInt(u16, 0); // outsideInfo / size
    try dev.buf.writeInt(u32, 0); // creationPCR / count

    try dev.sendReceive(null);

    const handle = try dev.buf.readInt(u32);
    if (pub_data != null) {
        _ = try dev.buf.readInt(u32); // params size
        _ = try dev.buf.readInt(u16); // outPublic / size
        if (dev.caps.ecc_curve != 0) {
            try dev.buf.expectInt(u16, defs.TPM_ALG_ECC); // outPublic / publicArea / type
        } else {
            try dev.buf.expectInt(u16, defs.TPM_ALG_RSA); // outPublic / publicArea / type
        }
        try dev.buf.expectInt(u16, dev.caps.hash_alg); // outPublic / publicArea / nameAlg
        _ = try dev.buf.readInt(u32); // outPublic / publicArea / objectAttributes
        try dev.buf.expectInt(u16, @intCast(auth_policy.len)); // outPublic / publicArea / authPolicy / size
        _ = try dev.buf.readSlice(auth_policy.len); // outPublic / publicArea / authPolicy / data
        try dev.buf.expectInt(u16, defs.TPM_ALG_AES); // outPublic / publicArea / [type]parameters / symmetric
        try dev.buf.expectInt(u16, dev.caps.aes_key_bits); // outPublic /publicArea / [type]parameters / rsaDetail | eccDetail / symmetric / keyBits
        try dev.buf.expectInt(u16, defs.TPM_ALG_CFB); // outPublic /publicArea / [type]parameters / rsaDetail | eccDetail / symmetric / mode
        try dev.buf.expectInt(u16, defs.TPM_ALG_NULL); // outPublic / publicArea / [type]parameters / rsaDetail | eccDetail / scheme
        if (dev.caps.ecc_curve != 0) {
            try dev.buf.expectInt(u16, dev.caps.ecc_curve); // outPublic / publicArea / [type]parameters / eccDetail / curveID
            try dev.buf.expectInt(u16, defs.TPM_ALG_NULL); // outPublic / publicArea / [type]parameters / eccDetail / kdf
            const ecc_key_size = try dev.buf.readInt(u16); // outPublic / publicArea / [type]unique / ecc / x / size
            if (2 * ecc_key_size != pub_data.?.len) {
                return TpmError.NoSuitableParameters;
            }
            try dev.buf.readIntoSlice(pub_data.?[0..ecc_key_size]);
            try dev.buf.expectInt(u16, ecc_key_size); // outPublic / publicArea / [type]unique / ecc / y / size
            try dev.buf.readIntoSlice(pub_data.?[ecc_key_size..]);
        } else {
            try dev.buf.expectInt(u16, dev.caps.rsa_key_bits); // inPublic /publicArea / [typeParameters] / rsaDetail / keyBits
            try dev.buf.expectInt(u32, defs.RSA_PUB_EXP); // inPublic /publicArea / [typeParameters] / rsaDetail / exponent
            const rsa_key_size = try dev.buf.readInt(u16); // inPublic / unique / rsa / size
            if (rsa_key_size != pub_data.?.len) {
                return TpmError.NoSuitableParameters;
            }
            try dev.buf.readIntoSlice(pub_data.?);
        }
    }
    return handle;
}

pub fn createLoaded(
    dev: *device.Device,
    primary_handle: u32,
    extra_flags: u32,
    payload: []const u8,
    auth_policy: []const u8,
) !u32 {
    if (payload.len > defs.MAX_PAYLOAD_SIZE) {
        return TpmError.PayloadIsTooLarge;
    }
    // TPM2_CreateLoaded() was deprecated in version 184 and some TPMs
    // don't support it => we have to compose Create + Load manually.
    try dev.buf.writeInt(u16, defs.TPM_ST_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_Create); // commandCode
    try dev.buf.writeInt(u32, primary_handle); // parentHandle
    try auth.writeAuthCommand(dev, defs.TPM_RS_PW);
    try dev.buf.writeInt(u16, @as(u16, @intCast(payload.len)) + 4); // inSensitive: size
    try dev.buf.writeInt(u16, 0); // userAuth: size
    try dev.buf.writeInt(u16, @intCast(payload.len)); // sensitiveData: size
    try dev.buf.writeSlice(payload);
    try dev.buf.writeInt(u16, 14 + dev.hash_size); // inPublic / size
    try dev.buf.writeInt(u16, defs.TPM_ALG_KEYEDHASH); // inPublic / publicArea / type
    try dev.buf.writeInt(u16, dev.caps.hash_alg); // inPublic / publicArea / nameAlg
    try dev.buf.writeInt(
        u32,
        defs.TPMA_OBJECT_fixedTPM | defs.TPMA_OBJECT_fixedParent | extra_flags,
    ); // inPublic / publicArea / objectAttributes
    try dev.buf.writeInt(u16, @intCast(auth_policy.len)); // inPublic / publicArea / authPolicy / size
    try dev.buf.writeSlice(auth_policy); // inPublic / publicArea / authPolicy / size / hash
    try dev.buf.writeInt(u16, defs.TPM_ALG_NULL); // inPublic /publicArea / [type]parameters / keyedHashDetail / scheme
    try dev.buf.writeInt(u16, 0); // inPublic / unique / digest / size
    try dev.buf.writeInt(u16, 0); // outsideInfo / size
    try dev.buf.writeInt(u32, 0); // creationPCR

    try dev.sendReceive(null);

    _ = try dev.buf.readInt(u32); // params size

    const private_size = try dev.buf.readInt(u16);
    var private: [common.BUFFER_SIZE]u8 = undefined;
    defer std.crypto.secureZero(u8, &private);
    try dev.buf.readIntoSlice(private[0..private_size]);

    const public_size = try dev.buf.readInt(u16);
    var public: [common.BUFFER_SIZE]u8 = undefined;
    try dev.buf.readIntoSlice(public[0..public_size]);

    try dev.buf.writeInt(u16, defs.TPM_ST_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_Load); // commandCode
    try dev.buf.writeInt(u32, primary_handle); // parentHandle
    try auth.writeAuthCommand(dev, defs.TPM_RS_PW);
    try dev.buf.writeInt(u16, private_size);
    try dev.buf.writeSlice(private[0..private_size]);
    try dev.buf.writeInt(u16, public_size);
    try dev.buf.writeSlice(public[0..public_size]);

    try dev.sendReceive(null);

    return try dev.buf.readInt(u32);
}

pub fn readPublic(dev: *device.Device, handle: u32, name: []u8) !void {
    try dev.buf.writeInt(u16, defs.TPM_ST_NO_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_ReadPublic); // commandCode
    try dev.buf.writeInt(u32, handle); // objectHandle

    try dev.sendReceive(null);

    const pub_size = try dev.buf.readInt(u16); // outPublic / size
    _ = try dev.buf.readSlice(pub_size);
    try dev.buf.expectInt(u16, dev.hash_size + 2); // name / size
    try dev.buf.expectInt(u16, dev.caps.hash_alg); // Hash type field
    try dev.buf.readIntoSlice(name);
}

pub fn unseal(
    dev: *device.Device,
    allocator: std.mem.Allocator,
    auth_session: u32,
    item_handle: u32,
    attrs: ?u8,
    hmac: ?[]const u8,
    nonce_tpm: ?[]u8,
) ![]u8 {
    try dev.buf.writeInt(u16, defs.TPM_ST_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_Unseal); // commandCode
    try dev.buf.writeInt(u32, item_handle); // itemHandle
    if (hmac != null) {
        try auth.writeAuthCommandWithHMAC(dev, auth_session, attrs.?, hmac.?);
    } else {
        try auth.writeAuthCommand(dev, auth_session);
    }

    try dev.sendReceive(null);

    const params_size = try dev.buf.readInt(u32); // params size
    const data_size = try dev.buf.readInt(u16);
    if (params_size != data_size + 2 or data_size + 16 > dev.buf.read_size) {
        return TpmError.InvalidResponse;
    }
    if (data_size > defs.MAX_PAYLOAD_SIZE) {
        return TpmError.InvalidResponse;
    }
    const content = allocator.dupe(u8, try dev.buf.readSlice(data_size));
    if (nonce_tpm != null) {
        try dev.buf.expectInt(u16, dev.hash_size);
        try dev.buf.readIntoSlice(nonce_tpm.?);
    }
    return content;
}
