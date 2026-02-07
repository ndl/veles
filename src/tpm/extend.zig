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

//! High-level API to TPM 'PCR extend' functionality.

const std = @import("std");

const common = @import("../common.zig");
const hashers = @import("hashers.zig");
const data = @import("data.zig");
const defs = @import("constants.zig");
const device = @import("device.zig");
const pcrs = @import("commands/pcrs.zig");

const TpmError = defs.TpmError;

pub fn extend(dev: *device.Device, pcr_index: u8, payload: []const u8) TpmError!void {
    var data_hash = try data.createHash(dev.caps.pcr_hash_alg);
    data_hash.deinit();
    try hashers.hash(dev.caps.pcr_hash_alg, payload, data_hash.slice());

    var hex_buf: [common.BUFFER_SIZE]u8 = undefined;
    const data_hash_hex = try common.toHex(data_hash.constSlice(), &hex_buf);
    std.log.debug(
        "Extending PCR {d} with hash '{s}'",
        .{ pcr_index, data_hash_hex },
    );

    try pcrs.extendPcr(dev, pcr_index, data_hash.constSlice());
}
