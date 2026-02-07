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

//! Root module for Veles TPM implementation.

pub const Capabilities = @import("tpm/constants.zig").Capabilities;
pub const Device = @import("tpm/device.zig").Device;

pub const extend = @import("tpm/extend.zig").extend;
pub const setup = @import("tpm/setup.zig").setup;
pub const unseal = @import("tpm/unseal.zig").unseal;
