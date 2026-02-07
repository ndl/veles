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

//! TPM commands for various capabilities discovery.

const std = @import("std");

const defs = @import("../constants.zig");
const device = @import("../device.zig");

const TpmError = defs.TpmError;

pub fn getSupportedEccCurve(dev: *device.Device) TpmError!u16 {
    try dev.buf.writeInt(u16, defs.TPM_ST_NO_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_GetCapability); // commandCode
    try dev.buf.writeInt(u32, defs.TPM_CAP_ECC_CURVES); // capability
    try dev.buf.writeInt(u32, 0); // property - shall be zero
    try dev.buf.writeInt(u32, 128); // max propertyCount

    dev.sendReceive(null) catch |err| {
        if (err == TpmError.TpmCommandFailed) {
            return 0;
        }
        return err;
    };

    _ = try dev.buf.readInt(u8); // moreData
    const capability = try dev.buf.readInt(u32);

    if (capability != defs.TPM_CAP_ECC_CURVES) {
        return TpmError.InvalidResponse;
    }

    // Both P384 and P256 SHALL be supported but some older TPMs
    // support P256 only.
    const pref_curves = [_]u16{ defs.TPM_ECC_NIST_P384, defs.TPM_ECC_NIST_P256 };
    var avail_curves = [_]bool{ false, false };

    const count = try dev.buf.readInt(u32);
    if (count == 0) {
        return 0;
    }

    for (0..count) |_| {
        const curve = try dev.buf.readInt(u16);
        if (std.mem.indexOfScalar(u16, &pref_curves, curve)) |idx| {
            avail_curves[idx] = true;
        }
    }

    for (pref_curves, 0..) |curve, idx| {
        if (avail_curves[idx]) {
            return curve;
        }
    }

    return 0;
}

pub fn getPcrBankConfig(
    dev: *device.Device,
    min_pcr_bank_size: u8,
    pcr_hash_alg: *u16,
    pcr_bank_size: *u8,
) TpmError!void {
    try dev.buf.writeInt(u16, defs.TPM_ST_NO_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_GetCapability); // commandCode
    try dev.buf.writeInt(u32, defs.TPM_CAP_PCRS); // capability
    try dev.buf.writeInt(u32, 0); // property - shall be zero
    try dev.buf.writeInt(u32, 128); // max propertyCount

    try dev.sendReceive(null);

    _ = try dev.buf.readInt(u8); // moreData - shall always be NO for PCRs
    const capability = try dev.buf.readInt(u32);

    if (capability != defs.TPM_CAP_PCRS) {
        return TpmError.InvalidResponse;
    }

    const pref_hashes = [_]u16{ defs.TPM_ALG_SHA256, defs.TPM_ALG_SHA1 };
    var avail_hashes = [_]bool{ false, false };
    var banks_sizes = [_]u8{ 0, 0 };

    const count = try dev.buf.readInt(u32);
    for (0..count) |_| {
        const hash = try dev.buf.readInt(u16);
        const sizeOfSelect = try dev.buf.readInt(u8);
        if (sizeOfSelect > 32) {
            return TpmError.InvalidResponse;
        }
        var bank_size: u8 = 0;
        var buf: [32]u8 = undefined;
        try dev.buf.readIntoSlice(buf[0..sizeOfSelect]);
        outer: for (0..sizeOfSelect) |byte_idx| {
            for (0..8) |bit_idx| {
                if (buf[byte_idx] & std.math.shl(u8, 1, bit_idx) == 0) {
                    break :outer;
                }
                bank_size += 1;
            }
        }
        if (bank_size < min_pcr_bank_size) {
            continue;
        }
        if (std.mem.indexOfScalar(u16, &pref_hashes, hash)) |idx| {
            avail_hashes[idx] = true;
            banks_sizes[idx] = bank_size;
        }
    }

    for (pref_hashes, 0..) |hash, idx| {
        if (avail_hashes[idx]) {
            pcr_hash_alg.* = hash;
            pcr_bank_size.* = banks_sizes[idx];
            return;
        }
    }

    std.log.err("No supported PCR banks found", .{});
    return TpmError.InvalidResponse;
}

pub fn hasTestParms(dev: *device.Device) TpmError!bool {
    try dev.buf.writeInt(u16, defs.TPM_ST_NO_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_GetCapability); // commandCode
    try dev.buf.writeInt(u32, defs.TPM_CAP_COMMANDS); // capability
    try dev.buf.writeInt(u32, defs.TPM_CC_TestParms); // property
    try dev.buf.writeInt(u32, 1); // max propertyCount

    try dev.sendReceive(null);

    _ = try dev.buf.readInt(u8); // moreData
    const capability = try dev.buf.readInt(u32);

    if (capability != defs.TPM_CAP_COMMANDS) {
        return TpmError.InvalidResponse;
    }

    try dev.buf.expectInt(u32, 1);
    const cmd = try dev.buf.readInt(u32);
    return cmd == defs.TPM_CC_TestParms;
}

pub fn processCapabilities(dev: *device.Device) TpmError!void {
    switch (dev.caps.hash_alg) {
        defs.TPM_ALG_SHA256 => {
            dev.hash_size = 32;
        },
        else => {
            return TpmError.NoSuitableParameters;
        },
    }
    switch (dev.caps.pcr_hash_alg) {
        defs.TPM_ALG_SHA1 => {
            dev.pcr_hash_size = 20;
        },
        defs.TPM_ALG_SHA256 => {
            dev.pcr_hash_size = 32;
        },
        else => {
            return TpmError.NoSuitableParameters;
        },
    }
    // The `unique` field for ECC is structured in the same format as ECC
    // public keys and thus must have the same total size as ECC public
    // keys combined.
    switch (dev.caps.ecc_curve) {
        defs.TPM_ECC_NIST_P256 => {
            dev.entropy_size = 64;
        },
        defs.TPM_ECC_NIST_P384 => {
            dev.entropy_size = 96;
        },
        0 => {
            // Calculate the size based on RSA key size.
            dev.entropy_size = dev.caps.rsa_key_bits / 8;
        },
        else => {
            return TpmError.NoSuitableParameters;
        },
    }
}

pub fn retrieveCapabilities(dev: *device.Device) TpmError!void {
    // Note: all "SHOULD", "SHOULD NOT" and "SHALL" comments here refer to
    // "TCG PC Client Platform TPM Profile Specification for TPM 2.0" v1.06.
    //
    // SHA256 algorithm SHALL be supported and so far I haven't seen any
    // TPM 2.0 implementations that don't support it.
    dev.caps.hash_alg = defs.TPM_ALG_SHA256;
    // SHA256 PCR banks SHALL be supported but some older TPMs use SHA1 only.
    // Also request PCR bank size of at least 16, although in practice it's unlikely
    // that anyone configures less than 24.
    try getPcrBankConfig(dev, 16, &dev.caps.pcr_hash_alg, &dev.caps.pcr_bank_size);
    std.log.debug(
        "Selected PCR hash: 0x{X}, PCR bank size: {d}",
        .{ dev.caps.pcr_hash_alg, dev.caps.pcr_bank_size },
    );
    dev.caps.ecc_curve = try getSupportedEccCurve(dev);
    // ECC SHALL be supported but some older TPMs don't support it.
    if (dev.caps.ecc_curve != 0) {
        std.log.debug("Selected ECC curve: 0x{X}", .{dev.caps.ecc_curve});
    } else {
        std.log.warn("ECC encryption not supported, switching to RSA", .{});
    }
    // TestParms SHALL be supported but some older TPMs don't support it.
    if (!try hasTestParms(dev)) {
        std.log.warn("TPM doesn't support defs.TPM_CC_TestParms, using minimally required keys sizes", .{});
        if (dev.caps.ecc_curve == 0) {
            // Both key sizes 2048 and 3072 SHALL be supported but
            // some older TPMs support 2048 only.
            dev.caps.rsa_key_bits = 2048;
        }
        // Both key sizes 128 and 256 SHALL be supported but some older
        // TPMs support 128 only.
        dev.caps.aes_key_bits = 128;
        return;
    }
    if (dev.caps.ecc_curve == 0) {
        // Both key sizes 2048 and 3072 SHALL be supported but
        // some older TPMs support 2048 only.
        for ([_]u16{ 4096, 3072, 2048 }) |key_bits| {
            if (try testRsaKeySize(dev, key_bits)) {
                dev.caps.rsa_key_bits = key_bits;
                std.log.debug("Selected RSA key size: {d}", .{key_bits});
                break;
            }
        }
        if (dev.caps.rsa_key_bits == 0) {
            std.log.err("TPM doesn't support any suitable RSA key size", .{});
            return TpmError.NoSuitableParameters;
        }
    }
    // Both key sizes 128 and 256 SHALL be supported but some older
    // TPMs support 128 only.
    for ([_]u16{ 256, 192, 128 }) |key_bits| {
        if (try testAesKeySize(dev, key_bits)) {
            dev.caps.aes_key_bits = key_bits;
            std.log.debug("Selected AES key size: {d}", .{key_bits});
            return;
        }
    }
    std.log.err("TPM doesn't support any suitable AES key size", .{});
    return TpmError.NoSuitableParameters;
}

pub fn testAesKeySize(dev: *device.Device, key_bits: u16) TpmError!bool {
    try dev.buf.writeInt(u16, defs.TPM_ST_NO_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_TestParms); // commandCode
    try dev.buf.writeInt(u16, defs.TPM_ALG_SYMCIPHER); // type
    try dev.buf.writeInt(u16, defs.TPM_ALG_AES); // [type]parameters / symDetail / sym / algorithm
    try dev.buf.writeInt(u16, key_bits); // [type]parameters / symDetail / sym / [algorithm]keyBits
    try dev.buf.writeInt(u16, defs.TPM_ALG_CFB); // [type]parameters / symDetail / sym / [algorithm]mode

    dev.sendReceive(null) catch |err| {
        if (err == TpmError.TpmCommandFailed) {
            return false;
        }
        return err;
    };

    return true;
}

pub fn testRsaKeySize(dev: *device.Device, key_bits: u16) TpmError!bool {
    try dev.buf.writeInt(u16, defs.TPM_ST_NO_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_TestParms); // commandCode
    try dev.buf.writeInt(u16, defs.TPM_ALG_RSA); // type
    try dev.buf.writeInt(u16, defs.TPM_ALG_NULL); // [type]parameters / rsaDetail / symmetric
    try dev.buf.writeInt(u16, defs.TPM_ALG_NULL); // [type]parameters / rsaDetail / scheme
    try dev.buf.writeInt(u16, key_bits); // [typeParameters] / rsaDetail / keyBits
    try dev.buf.writeInt(u32, defs.RSA_PUB_EXP); // [typeParameters] / rsaDetail / exponent

    dev.sendReceive(null) catch |err| {
        if (err == TpmError.TpmCommandFailed) {
            return false;
        }
        return err;
    };

    return true;
}
