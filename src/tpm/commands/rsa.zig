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

//! Limited RSA-OAEP implementation that is sufficient for
//! establishing TPM2 salted auth sessions.

// OAEP implementation is according to
// https://datatracker.ietf.org/doc/html/rfc8017#section-7.1.1
//
// Relevant code bases that were helpful in the implementation:
// * https://github.com/traszka116/RSA-zig
// * https://github.com/NefixEstrada/zig-rsa

const std = @import("std");

const data = @import("../data.zig");
const defs = @import("../constants.zig");
const hashers = @import("../hashers.zig");

const Limb = usize;
const Managed = std.math.big.int.Managed;
const TpmError = defs.TpmError;

fn mgf1Xor(hash_alg: u16, out: []u8, seed: []const u8) TpmError!void {
    var hash = try data.createHash(hash_alg);
    defer hash.deinit();

    var counter: u32 = 0;
    var counter_buf: [4]u8 = undefined;

    var out_pos: usize = 0;
    while (true) {
        var hasher = try hashers.createHasher(hash_alg);
        hasher.update(seed);
        std.mem.writeInt(u32, &counter_buf, counter, .big);
        hasher.update(&counter_buf);
        hasher.final(hash.slice());

        for (0..hash.size) |hash_pos| {
            if (out_pos >= out.len) {
                return;
            }
            out[out_pos] ^= hash.slice()[hash_pos];
            out_pos += 1;
        }

        counter += 1;
    }
}

fn modExp(base: Managed, exp: usize, mod: Managed) !Managed {
    var b = try Managed.init(base.allocator);
    defer b.deinit();

    var tmp = try Managed.init(base.allocator);
    defer tmp.deinit();

    try tmp.divTrunc(&b, &base, &mod);

    var r = try Managed.init(base.allocator);
    errdefer r.deinit();
    try r.set(1);

    var e = exp;
    while (e != 0) {
        if (e % 2 == 1) {
            try r.mul(&r, &b);
            try tmp.divTrunc(&r, &r, &mod);
        }
        try b.sqr(&b);
        try tmp.divTrunc(&b, &b, &mod);
        e >>= 1;
    }
    try r.truncate(&r, .unsigned, base.metadata * @sizeOf(Limb) * 8);
    return r;
}

pub fn fromBytes(value: *Managed, buf: []const u8) TpmError!void {
    if (buf.len % @sizeOf(Limb) != 0) {
        return TpmError.NoSuitableParameters;
    }
    value.allocator.free(value.limbs);
    const len = buf.len / @sizeOf(Limb);
    value.metadata = len;
    value.limbs = try value.allocator.alloc(Limb, @max(Managed.default_capacity, len));
    for (0..len) |idx| {
        value.limbs[len - idx - 1] = std.mem.readInt(
            Limb,
            buf[@sizeOf(Limb) * idx ..][0..@sizeOf(Limb)],
            .big,
        );
    }
}

pub fn toBytes(value: Managed, buf: []u8) TpmError!void {
    const len = value.metadata;
    if (buf.len < len * @sizeOf(Limb)) {
        return TpmError.NoSuitableParameters;
    }
    for (0..len) |idx| {
        std.mem.writeInt(
            Limb,
            buf[idx * @sizeOf(Limb) ..][0..@sizeOf(Limb)],
            value.limbs[len - idx - 1],
            .big,
        );
    }
}

fn encrypt(pub_key: []const u8, out: []u8) TpmError!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator: std.mem.Allocator = arena.allocator();

    var em = try Managed.init(allocator);
    defer em.deinit();
    try fromBytes(&em, out);

    var n = try Managed.init(allocator);
    defer n.deinit();
    try fromBytes(&n, pub_key);

    var c = try modExp(em, defs.RSA_PUB_EXP_ACTUAL, n);
    defer c.deinit();

    try toBytes(c, out);
}

pub fn encryptWithOaep(
    hash_alg: u16,
    pub_key: []const u8,
    payload: []const u8,
    label: []const u8,
    out: []u8,
) TpmError!void {
    var hasher = try hashers.createHasher(hash_alg);
    const hash_size = hasher.size();

    // The format of EM, as per
    // https://datatracker.ietf.org/doc/html/rfc8017#section-7.1.1
    // is as follows:
    // 0x00 || maskedSeed || maskedDB
    const seed = out[1 .. hash_size + 1];
    var db = out[hash_size + 1 ..];

    std.crypto.random.bytes(seed);

    // The format of DB is
    // hash(label) || <zero padding> || 0x01 || payload
    hasher.update(label);
    hasher.final(db[0..hash_size]);

    db[db.len - payload.len - 1] = 1;
    @memcpy(db[db.len - payload.len ..], payload);

    try mgf1Xor(hash_alg, db, seed);
    try mgf1Xor(hash_alg, seed, db);

    try encrypt(pub_key, out);
}
