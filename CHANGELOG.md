# Change Log

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
