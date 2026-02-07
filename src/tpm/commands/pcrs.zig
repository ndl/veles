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

//! TPM commands for operations on PCRs.

const std = @import("std");

const auth = @import("auth.zig");
const data = @import("../data.zig");
const defs = @import("../constants.zig");
const device = @import("../device.zig");
const hashers = @import("../hashers.zig");

const TpmError = defs.TpmError;

pub fn extendPcr(dev: *device.Device, pcr_index: u8, hash: []const u8) TpmError!void {
    try dev.buf.writeInt(u16, defs.TPM_ST_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_PCR_Extend); // commandCode
    try dev.buf.writeInt(u32, pcr_index); // PCR
    try auth.writeAuthCommand(dev, defs.TPM_RS_PW);
    try dev.buf.writeInt(u32, 1); // num digests
    try dev.buf.writeInt(u16, dev.caps.pcr_hash_alg); // hashAlg
    try dev.buf.writeSlice(hash);

    try dev.sendReceive(19);
}

pub fn getPcrValue(dev: *device.Device, pcr_index: u8, value: []u8) TpmError!void {
    try dev.buf.writeInt(u16, defs.TPM_ST_NO_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_PCR_Read); // commandCode
    try writeSelectPcrs(dev, &[_]u8{pcr_index});

    try dev.sendReceive(null);

    _ = try dev.buf.readInt(u32); // pcrUpdateCounter
    try dev.buf.expectInt(u32, 1); // pcrSelectionCount
    try dev.buf.expectInt(u16, dev.caps.pcr_hash_alg);
    const sizeOfSelect = try dev.buf.readInt(u8); // PCR bitmask size
    _ = try dev.buf.readSlice(sizeOfSelect); // PCR bitmask
    try dev.buf.expectInt(u32, 1); // num digests
    try dev.buf.expectInt(u16, dev.pcr_hash_size);
    try dev.buf.readIntoSlice(value);
}

pub fn policyPcr(
    dev: *device.Device,
    session_handle: u32,
    pcrs_indices: []const u8,
    pcr_content: ?[]const u8,
) TpmError!void {
    try dev.buf.writeInt(u16, defs.TPM_ST_NO_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_PolicyPCR); // commandCode
    try dev.buf.writeInt(u32, session_handle); // policySession
    if (pcr_content != null) {
        try dev.buf.writeInt(u16, dev.hash_size); // pcrDigest: size
        try dev.buf.writeSlice(pcr_content.?);
    } else {
        try dev.buf.writeInt(u16, 0); // pcrDigest: none
    }
    _ = try writeSelectPcrs(dev, pcrs_indices);

    try dev.sendReceive(10);
}

pub fn calculateExpectedPcrsHash(
    dev: *device.Device,
    pcrs_indices: []const u8,
    extend_pcr_index: u8,
    content: []const u8,
    output: []u8,
) TpmError!void {
    var content_hash = try data.createHash(dev.caps.pcr_hash_alg);
    content_hash.deinit();
    try hashers.hash(dev.caps.pcr_hash_alg, content, content_hash.slice());
    var hasher = try hashers.createHasher(dev.caps.hash_alg);
    var folding_hash = try data.createHash(dev.caps.pcr_hash_alg);
    for (pcrs_indices) |pcr_index| {
        if (pcr_index != extend_pcr_index) {
            try getPcrValue(dev, pcr_index, folding_hash.slice());
        } else {
            var pcr_hasher = try hashers.createHasher(dev.caps.pcr_hash_alg);
            var pcr_folding_hash = try data.createHash(dev.caps.pcr_hash_alg);
            pcr_hasher.update(pcr_folding_hash.constSlice());
            pcr_hasher.update(content_hash.constSlice());
            pcr_hasher.final(folding_hash.slice());
        }
        hasher.update(folding_hash.slice());
    }
    hasher.final(output);
}

fn writeSelectPcrs(dev: *device.Device, pcrs_indices: []const u8) TpmError!void {
    const sizeOfSelect = (dev.caps.pcr_bank_size + 7) / 8;
    var pcrs = data.Array(32).init(sizeOfSelect);
    for (pcrs_indices) |pcr_index| {
        if (pcr_index >= dev.caps.pcr_bank_size) {
            return TpmError.InvalidPcrIndex;
        }
        pcrs.slice()[pcr_index / 8] |= std.math.shl(u8, 1, pcr_index % 8);
    }
    try dev.buf.writeInt(u32, 1); // pcrSelectionIn:count
    try dev.buf.writeInt(u16, dev.caps.pcr_hash_alg); // pcrSelectionIn:hash
    try dev.buf.writeInt(u8, sizeOfSelect); // pcrSelectionIn:sizeOfSelect
    try dev.buf.writeSlice(pcrs.constSlice());
}
