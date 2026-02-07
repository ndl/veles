# Veles

## What?

Veles is a tool to setup and use TPM-based ZFS datasets encryption on Linux systems.

This setup enables ZFS encryption without entering the password on each boot, but comes
with its own set of trade-offs.

## Why?

Mostly because I couldn't find an existing solution:

* `systemd-cryptenroll`, `clevis` etc mainly / only target LUKS.
* No tools I could find perform ZFS datasets authentication to prevent "filesystem replacement"
  type of attacks.

But also the fact that I wanted to play with TPMs for quite some time and finally found a bit
of time + an excuse did likely play a role :-)

## For whom?

Highly experienced Linux users / administrators / security professionals who **really**
understand what they're doing.

## How?

Veles is **by no means plug-and-play** - it requires **careful integration** into boot process.
See [Integration](docs/Integration.md) for details.

## Stability / maturity

"Surely you can't be serious" (C) :-)

Veles was written as a hobby project in some evenings + weekends by a person who has no relevant
security background in a language they had no idea even existed before they started and then was
tested on just a couple of PCs.

If you use it for anything other than experiments or on any system that has valuable data - you
fail the requirement above of **really** understanding what you're doing, so Veles is
**definitely** not for you.

In particular, note that there's **no backward or forward compatibility at all**. Any Veles
release might (and likely will) break all previous setups and requires re-running `setup` to
ensure the system is still bootable.

## Security vulnerabilities

Don't bother with a proper "disclosure process" - Veles is not at the stage where this matters
and I might not have time to respond promptly to these anyway. Just open a normal bug in "Issues"
project tab on GitHub, but please check [Security](docs/Security.md) first to verify that what
you're going to report is not "out of scope" for protections offered by Veles.

## Requirements

* TPM 2.0.
* Secure Boot.
* All relevant ZFS datasets are encrypted.
* (optional, but recommended) systemd is enabled at initrd stage of the boot.

## License

Copyright (C) 2026 Alexander Tsvyashchenko <veles@endl.ch>, [GPLv3](https://spdx.org/licenses/GPL-3.0-only.html).

## Support or further development

I don't intend to spend a lot more time on Veles - I wrote it for my own purposes and I'm
releasing it in the hope it might also be useful for someone but without any commitments
whatsoever, including either support or future development.

Therefore you should keep your expectations low in terms of my responses to any feature requests
or issues. I'm more likely to respond to security-related issues within "in scope" protections
(see [Security](docs/Security.md)) or if the issue / feature request is accompanied by pull
request with the corresponding tests added to `tests/veles.bats`.

## Why this name?

"Veles" is the name of one of the [old Slavic gods](https://en.wikipedia.org/wiki/Veles_(god)) who,
among other things, was used in / responsible for oaths - which seems to be fitting.

## Why Zig?

Veles is implemented in [Zig language](https://ziglang.org/) as it provides a favourable balance
between language features, standard library functionality and target binary size.

More specifically:

* Veles needs to be placed into initrd disk image which, due to multiple reasons, should be kept
  relatively small.
* Veles uses both the functionality considered "basic" these days like hashmaps or JSON parsing,
  but also some crypto functionality like hashing and ECC operations.

All of the "more mainstream" languages I've briefly tested (Rust, Go, C++ and even C with
corresponding third-party libs) would produce binaries sizes measured in multiple megabytes for
the intended functionality, whereas current Veles size written in Zig is less than 400K.

## Further documentation

* [Integration](docs/Integration.md): Veles usage and integration into boot process.
* [Security](docs/Security.md): what does Veles intend to protect you from?
* [Limitations](docs/Limitations.md): both current and fundamental Veles limitations.
* [MultiBoot](docs/MultiBoot.md): what to do if you need to multi-boot into other systems.
