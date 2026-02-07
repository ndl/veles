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

//! High-level API to perform TPM setup for verification purposes.

const std = @import("std");

const common = @import("../common.zig");
const data = @import("data.zig");
const defs = @import("constants.zig");
const device = @import("device.zig");
const extend = @import("extend.zig");
const handles = @import("commands/handles.zig");
const hashers = @import("hashers.zig");
const keys = @import("commands/keys.zig");
const pcrs = @import("commands/pcrs.zig");
const sessions = @import("commands/sessions.zig");

const TpmError = defs.TpmError;

pub fn setup(
    dev: *device.Device,
    slot: u32,
    pcrs_indices: []const u8,
    extend_pcr_index: u8,
    force: bool,
    passwords: []const u8,
    meta: []const u8,
) TpmError!u32 {
    var persistent_handle: u32 = 0;

    if (slot != 0) {
        persistent_handle = slot;
        std.log.info("Using requested TPM persistent handle: 0x{X}", .{persistent_handle});
        handles.evictControl(dev, persistent_handle, persistent_handle) catch |err| {
            std.log.warn(
                "Evicting TPM persistent handle 0x{X} failed: {t}",
                .{ persistent_handle, err },
            );
        };
    } else {
        persistent_handle = try handles.getFreePersistentHandle(dev);
        std.log.info("Using first free TPM persistent handle: 0x{X}", .{persistent_handle});
    }

    var pcr = try data.createHash(dev.caps.pcr_hash_alg);
    defer pcr.deinit();

    try pcrs.getPcrValue(dev, extend_pcr_index, pcr.slice());

    if (!std.mem.allEqual(u8, pcr.constSlice(), 0)) {
        if (force) {
            std.log.err(
                "PCR {d} is non-zero / might be in use but 'force' was specified - continuing.",
                .{extend_pcr_index},
            );
        } else {
            std.log.err(
                "PCR {d} is non-zero / might be in use, refusing to extend",
                .{extend_pcr_index},
            );
            return TpmError.PcrInUse;
        }
    } else {
        try extend.extend(dev, extend_pcr_index, meta);
    }

    var exp_pcrs_hash = try data.createHash(dev.caps.hash_alg);
    defer exp_pcrs_hash.deinit();

    try pcrs.calculateExpectedPcrsHash(
        dev,
        pcrs_indices,
        extend_pcr_index,
        meta,
        exp_pcrs_hash.slice(),
    );

    var session_entropy = try data.createHash(dev.caps.hash_alg);
    defer session_entropy.deinit();
    std.crypto.random.bytes(session_entropy.slice());

    const session_handle = try sessions.startAuthSession(dev, true, session_entropy.constSlice());

    var init_auth_policy = try data.createHash(dev.caps.hash_alg);
    defer init_auth_policy.deinit();

    try sessions.policyGetDigest(dev, session_handle, init_auth_policy.slice());

    var auth_policy = try data.createHash(dev.caps.hash_alg);
    defer auth_policy.deinit();

    try pcrs.policyPcr(dev, session_handle, pcrs_indices, exp_pcrs_hash.constSlice());
    try sessions.policyGetDigest(dev, session_handle, auth_policy.slice());

    try handles.flushContext(dev, session_handle);

    var primary_entropy = data.createEntropy(dev.entropy_size);
    defer primary_entropy.deinit();
    std.crypto.random.bytes(primary_entropy.slice());

    const primary_handle = try keys.createPrimary(
        dev,
        defs.TPMA_OBJECT_restricted |
            defs.TPMA_OBJECT_decrypt |
            defs.TPMA_OBJECT_userWithAuth,
        primary_entropy.constSlice(),
        &[0]u8{},
        null,
    );
    defer handles.flushContext(dev, primary_handle) catch {};

    const keys_handle = try keys.createLoaded(
        dev,
        primary_handle,
        0,
        passwords,
        auth_policy.constSlice(),
    );

    try handles.evictControl(dev, keys_handle, persistent_handle);
    return persistent_handle;
}
