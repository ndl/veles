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

//! TPM-related data types for storing variable-sized arrays
//! with known max size such as hashes and ECC coordinates (that are limited
//! by max algorithm we support).

const std = @import("std");
const defs = @import("constants.zig");

pub const TpmError = error{
    NoSuitableParameters,
};

pub fn Array(comptime max_size: comptime_int) type {
    return struct {
        data: [max_size]u8,
        size: u16,

        const Self = @This();

        pub fn init(size: u16) Self {
            var self = Self{
                .size = size,
                .data = undefined,
            };
            @memset(self.data[0..max_size], 0);
            return self;
        }

        pub fn deinit(self: *Self) void {
            std.crypto.secureZero(u8, &self.data);
        }

        pub fn slice(self: *Self) []u8 {
            return self.data[max_size - self.size .. max_size];
        }

        pub fn constSlice(self: *const Self) []const u8 {
            return self.data[max_size - self.size .. max_size];
        }
    };
}

pub const Hash = Array(defs.MAX_DIGEST_SIZE);

pub fn createHash(alg: u16) TpmError!Hash {
    const size: u16 = switch (alg) {
        defs.TPM_ALG_SHA1 => 20,
        defs.TPM_ALG_SHA256 => 32,
        else => return TpmError.NoSuitableParameters,
    };
    return Hash.init(size);
}

pub const Entropy = Array(defs.MAX_ENTROPY_SIZE);

pub fn createEntropy(size: u16) Entropy {
    return Entropy.init(size);
}

pub const EccCoord = Array(defs.MAX_ECC_KEY_SIZE);

pub fn createEccCoord(alg: u16) TpmError!EccCoord {
    const size: u16 = switch (alg) {
        defs.TPM_ECC_NIST_P256 => 32,
        defs.TPM_ECC_NIST_P384 => 48,
        else => return TpmError.NoSuitableParameters,
    };
    return EccCoord.init(size);
}

pub const EccPoint = Array(2 * defs.MAX_ECC_KEY_SIZE);

pub fn createEccPoint(alg: u16) TpmError!EccPoint {
    const coord_size: u16 = switch (alg) {
        defs.TPM_ECC_NIST_P256 => 32,
        defs.TPM_ECC_NIST_P384 => 48,
        else => return TpmError.NoSuitableParameters,
    };
    return EccPoint.init(2 * coord_size);
}

pub const RsaKey = Array(defs.MAX_RSA_KEY_SIZE);

pub fn createRsaKey(rsa_key_bits: u16) TpmError!RsaKey {
    if (rsa_key_bits <= 8 * defs.MAX_RSA_KEY_SIZE and rsa_key_bits % 8 == 0) {
        return RsaKey.init(rsa_key_bits / 8);
    } else {
        return TpmError.NoSuitableParameters;
    }
}

pub const AesAndIV = Array(defs.MAX_AES_COMBINED_SIZE);

pub fn createAesAndIV(aes_key_bits: u16) TpmError!AesAndIV {
    if (aes_key_bits % 8 == 0 and aes_key_bits <= defs.MAX_AES_KEY_SIZE * 8) {
        return AesAndIV.init(aes_key_bits / 8 + defs.AES_IV_SIZE);
    } else {
        return TpmError.NoSuitableParameters;
    }
}
