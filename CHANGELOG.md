# Change Log

## [0.3.7] - 2026-03-01

## Changed

* Retrieve from ZFS only the properties we need for verification. This prevents an issue
  with custom properties encoding where, depending on the locale settings, the output of
  `zig get` might terminate prematurely if some properties values contain non-ASCII chars.
  Also this simplifies the logic a bit and reduces dependencies + binary size because we
  don't need to test which properties to hash anymore.
* (related to above) Fixed a bug where the order of properties in single dataset properties
  hashing was not stable.
* Fixed a bug where `--keep_keys` option in combination with fallback mode was causing
  verification to succeed even if the passwords were not entered manually but provided
  from `load`.

## Update instructions

* Due to the properties ordering bugfix the hashes will change, therefore **re-running
  setup is required**.

## [0.3.6] - 2026-02-14

### Added

* Implemented fallback option for `verify` stage. Now it's possible to skip `verify` failed
  check if the passwords for all encryption roots were entered manually in any of the `load`
  or `verify` stages (unless `--no_fallback` option is set).
* Fixed `verify` stage 2 integration in NixOS example to block the boot until it succeeds.

### Update instructions

* The formats of the configs / hashes didn't change - re-running `setup` isn't necessary.
* Integration calls for `verify` might need to be adjusted depending on whether you want
  to keep the newly introduced fallback option for `verify` enabled or not and whether
  you want to use `--systemd_ask_password` for fallback passwords prompt in `verify`.
  NixOS module example was updated accordingly.

## [0.3.5] - 2026-02-07

Initial public release.
