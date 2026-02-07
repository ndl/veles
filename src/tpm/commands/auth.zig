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

//! Auth-related TPM helpers.

const defs = @import("../constants.zig");
const device = @import("../device.zig");

const TpmError = defs.TpmError;

pub fn writeAuthCommand(dev: *device.Device, auth_session: u32) TpmError!void {
    try dev.buf.writeInt(u32, 9); // auth cmd size
    try dev.buf.writeInt(u32, auth_session); // sessionHandle
    try dev.buf.writeInt(u16, 0); // nonce: empty buffer
    try dev.buf.writeInt(u8, 0); // sessionAttributes
    try dev.buf.writeInt(u16, 0); // hmac: empty buffer
}

pub fn writeAuthCommandWithHMAC(
    dev: *device.Device,
    auth_session: u32,
    attrs: u8,
    hmac: []const u8,
) TpmError!void {
    try dev.buf.writeInt(u32, @intCast(9 + hmac.len)); // auth cmd size
    try dev.buf.writeInt(u32, auth_session); // sessionHandle
    try dev.buf.writeInt(u16, 0); // nonce: empty buffer
    try dev.buf.writeInt(u8, attrs); // sessionAttributes
    try dev.buf.writeInt(u16, @intCast(hmac.len)); // hmac: size
    try dev.buf.writeSlice(hmac);
}
