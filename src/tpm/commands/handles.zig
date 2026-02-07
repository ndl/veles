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

//! TPM commands for operations on handles.

const auth = @import("auth.zig");
const defs = @import("../constants.zig");
const device = @import("../device.zig");

const TpmError = defs.TpmError;

pub fn getFreePersistentHandle(dev: *device.Device) TpmError!u32 {
    var last_handle: u32 = defs.TPM_HT_PERSISTENT;

    while (true) {
        try dev.buf.writeInt(u16, defs.TPM_ST_NO_SESSIONS); // tag
        try dev.buf.writeInt(u32, 0); // commandSize, filled in later
        try dev.buf.writeInt(u32, defs.TPM_CC_GetCapability); // commandCode
        try dev.buf.writeInt(u32, defs.TPM_CAP_HANDLES); // capability
        try dev.buf.writeInt(u32, last_handle + 1); // property
        try dev.buf.writeInt(u32, 128); // max propertyCount

        try dev.sendReceive(null);

        const moreData = try dev.buf.readInt(u8);
        const capability = try dev.buf.readInt(u32);

        if (capability != defs.TPM_CAP_HANDLES) {
            return TpmError.InvalidResponse;
        }

        const count = try dev.buf.readInt(u32);
        if (4 * count != dev.buf.read_size - 19) {
            return TpmError.InvalidResponse;
        }

        for (0..count) |_| {
            const handle = try dev.buf.readInt(u32);
            if (handle > last_handle + 1) {
                return last_handle + 1;
            }
            last_handle = handle;
        }

        if (moreData == 0) {
            break;
        }
    }
    return last_handle + 1;
}

pub fn evictControl(dev: *device.Device, item_handle: u32, persistent_handle: u32) !void {
    try dev.buf.writeInt(u16, defs.TPM_ST_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_EvictControl); // commandCode
    try dev.buf.writeInt(u32, defs.TPM_RH_OWNER); // @auth
    try dev.buf.writeInt(u32, item_handle); // objectHandle
    try auth.writeAuthCommand(dev, defs.TPM_RS_PW);
    try dev.buf.writeInt(u32, persistent_handle); // persistentHandle

    try dev.sendReceive(19);
}

pub fn flushContext(dev: *device.Device, session_handle: u32) TpmError!void {
    try dev.buf.writeInt(u16, defs.TPM_ST_NO_SESSIONS); // tag
    try dev.buf.writeInt(u32, 0); // commandSize, filled in later
    try dev.buf.writeInt(u32, defs.TPM_CC_FlushContext); // commandCode
    try dev.buf.writeInt(u32, session_handle); // policySession

    try dev.sendReceive(10);
}
