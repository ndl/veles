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

//! Implementation of CFB symmetric cypher decryption mode that's missing
//! in Zig standard library as of version 0.15.2.

const std = @import("std");

pub fn cfb(
    comptime BlockCipher: anytype,
    block_cipher: BlockCipher,
    dst: []u8,
    src: []const u8,
    iv: [BlockCipher.block_length]u8,
) void {
    const block_size = BlockCipher.block_length;
    std.debug.assert(dst.len >= src.len);
    std.debug.assert(iv.len >= block_size);
    var prev_block: [block_size]u8 = undefined;
    var pos: usize = 0;

    @memcpy(&prev_block, &iv);

    while (pos + block_size <= src.len) : (pos += block_size) {
        const cur_block: [block_size]u8 = src[pos..][0..block_size].*;
        block_cipher.xor(dst[pos..][0..block_size], src[pos..][0..block_size], prev_block);
        @memcpy(&prev_block, &cur_block);
    }

    if (pos < src.len) {
        var padded: [block_size]u8 = undefined;
        @memcpy(padded[0 .. src.len - pos], src[pos..src.len]);
        block_cipher.xor(&padded, &padded, prev_block);
        @memcpy(dst[pos..src.len], padded[0 .. src.len - pos]);
    }
}
