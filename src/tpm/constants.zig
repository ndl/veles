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

//! TPM-related constants, mostly taken from the corresponding
//! TCG specifications.

const std = @import("std");

pub const AES_IV_SIZE = 16;

// We support up to AES256 key size.
pub const MAX_AES_KEY_SIZE = 32;
pub const MAX_AES_COMBINED_SIZE = MAX_AES_KEY_SIZE + AES_IV_SIZE;
// We support up to SHA256 for PCRs hashes
// and hard-code SHA256 as a general hash algorithm.
pub const MAX_DIGEST_SIZE = 32;
// We support up to P384 ECC curves.
pub const MAX_ECC_KEY_SIZE = 48;
// We support up to RSA4096 key size.
pub const MAX_RSA_KEY_SIZE = 512;
// Max entropy that is used in RSA case,
// equals max RSA key size.
pub const MAX_ENTROPY_SIZE = 512;
// From TPM spec.
pub const MAX_PAYLOAD_SIZE = 128;

// The value of 0 indicates 2^16 + 1 and is in fact expected
// by some TPMs so that it matches default EK template.
pub const RSA_PUB_EXP = 0;
// The actual value this default RSA exponent corresponds to,
// for the real calculations.
pub const RSA_PUB_EXP_ACTUAL = 65537;

pub const TPMA_OBJECT_decrypt = 1 << 17;
pub const TPMA_OBJECT_encrypt = 1 << 18;
pub const TPMA_OBJECT_fixedParent = 1 << 4;
pub const TPMA_OBJECT_fixedTPM = 1 << 1;
pub const TPMA_OBJECT_restricted = 1 << 16;
pub const TPMA_OBJECT_sensitiveDataOrigin = 1 << 5;
pub const TPMA_OBJECT_userWithAuth = 1 << 6;
pub const TPMA_OBJECT_adminWithPolicy = 1 << 7;

pub const TPMA_SESSION_decrypt = 1 << 5;
pub const TPMA_SESSION_encrypt = 1 << 6;

pub const TPM_ALG_AES = 0x0006;
pub const TPM_ALG_CFB = 0x0043;
pub const TPM_ALG_ECC = 0x0023;
pub const TPM_ALG_KEYEDHASH = 0x0008;
pub const TPM_ALG_SYMCIPHER = 0x0025;
pub const TPM_ALG_NULL = 0x0010;
pub const TPM_ALG_RSA = 0x0001;
pub const TPM_ALG_SHA1 = 0x0004;
pub const TPM_ALG_SHA256 = 0x000B;

pub const TPM_CAP_COMMANDS = 0x00000002;
pub const TPM_CAP_ECC_CURVES = 0x00000008;
pub const TPM_CAP_HANDLES = 0x00000001;
pub const TPM_CAP_PCRS = 0x00000005;

pub const TPM_CC_Create = 0x00000153;
pub const TPM_CC_CreatePrimary = 0x00000131;
pub const TPM_CC_EvictControl = 0x00000120;
pub const TPM_CC_FlushContext = 0x00000165;
pub const TPM_CC_GetCapability = 0x0000017A;
pub const TPM_CC_Load = 0x00000157;
pub const TPM_CC_LoadExternal = 0x00000167;
pub const TPM_CC_PCR_Extend = 0x00000182;
pub const TPM_CC_PCR_Read = 0x0000017E;
pub const TPM_CC_PolicyGetDigest = 0x00000189;
pub const TPM_CC_PolicyPCR = 0x0000017F;
pub const TPM_CC_ReadPublic = 0x00000173;
pub const TPM_CC_StartAuthSession = 0x00000176;
pub const TPM_CC_TestParms = 0x0000018A;
pub const TPM_CC_Unseal = 0x0000015E;

pub const TPM_ECC_NIST_P256 = 0x0003;
pub const TPM_ECC_NIST_P384 = 0x0004;

pub const TPM_HT_PERSISTENT = 0x81000000;

pub const TPM_RC_SUCCESS = 0x000;

pub const TPM_RH_ENDORSEMENT = 0x4000000B;
pub const TPM_RH_NULL = 0x40000007;
pub const TPM_RH_OWNER = 0x40000001;

pub const TPM_RS_PW = 0x40000009;

pub const TPM_SE_POLICY = 0x01;
pub const TPM_SE_TRIAL = 0x03;

pub const TPM_ST_NO_SESSIONS = 0x8001;
pub const TPM_ST_SESSIONS = 0x8002;

pub const TPM_SECRET_KEY: [7]u8 = .{ 'S', 'E', 'C', 'R', 'E', 'T', 0 };
pub const TPM_ATH_KEY: [4]u8 = .{ 'A', 'T', 'H', 0 };
pub const TPM_CFB_KEY: [4]u8 = .{ 'C', 'F', 'B', 0 };
// IWG (TCG Infrastructure Work Group) default EK primary key policy.
// See "TCG EK Credential Profile" specification, section 2.1.5,
// "Default EK Public Area Template".
// zig fmt: off
pub const TPM_IWG_EK_AUTH_POLICY: [32]u8 = .{
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
    0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
    0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
    0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
};
// zig fmt: on

pub const TpmError = error{
    EccOperationError,
    InternalError,
    InvalidPcrIndex,
    InvalidResponse,
    NoSuitableParameters,
    OpenFailed,
    PayloadIsTooLarge,
    PcrInUse,
    ReadFailed,
    RequestIsTooLarge,
    ResponseTooShort,
    TpmCommandFailed,
    WriteFailed,
} ||
    std.posix.OpenError ||
    std.posix.WriteError ||
    std.posix.ReadError ||
    std.mem.Allocator.Error ||
    error{SizeMismatch};

pub const Capabilities = struct {
    hash_alg: u16 = 0,
    pcr_hash_alg: u16 = 0,
    pcr_bank_size: u8 = 0,
    ecc_curve: u16 = 0,
    rsa_key_bits: u16 = 0,
    aes_key_bits: u16 = 0,
};
