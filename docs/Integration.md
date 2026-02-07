# Integration

**TL;DR**:

* Understand what you're doing **really well**.
* Have recovery image ready.
* Consult `nixos` directory for NixOS integration example.

## Prerequisites

### Secure Boot

Strictly speaking, Secure Boot is not required - but it is highly recommended and you probably
shouldn't even bother with this whole setup if you don't have it.

Without Secure Boot you'll have to measure the whole boot path using multiple PCRs that contain
the hashes of the components called during the boot. This is highly fragile both because it's
easy to miss one of the important components and because these hashes will change each time any
of the components is updated such as kernel, bootloader or UEFI update. Every change will render
your system unbootable, so you'll need to enter the passwords manually and then re-run setup.

It's also highly recommended to set administrator password on entering BIOS to reduce attack
surface.

I think [Lanzaboote](https://nix-community.github.io/lanzaboote/getting-started/prepare-your-system.html)
tutorial provides a reasonable description of the steps required. You can follow it even if you
use different bootloader - just replace the bootloader-specific parts with what you use.

### TPM

TPM requirements:

* Supports the 2.0 standard.
* Supports at least one of SHA-256 or SHA-1 PCR banks.
* Supports SHA-256 hashing algorithm.
* Supports at least one of the following asymmetric encryption algorithms: ECC NIST 384,
  ECC NIST 256, RSA 4096, RSA 3072, RSA 2048.
* Supports at least one of the following symmetric encryption algorithms: AES 256, AES 192,
  AES 128.
* Has at least one free persistent slot.

I expect all real-world TPM 2.0 compliant implementations to satisfy these requirements.

### Bootloader

Bootloader requirements:

* Supports Secure Boot, that is:
  * Signed with correct keys.
  * Verifies the integrity of any system it boots - including any extra relevant data like
    initrd images.
  * Restricts what systems and with what parameters can be booted. In particular, no unsigned
    systems should be bootable and no modifications to system parameters (such as editing kernel
    command line) should be possible.
* Ideally, performs TPM PCR extensions based on the OS being booted (especially important if you
  use multi-boot, see [MultiBoot](MultiBoot.md)).

### ZFS setup

* All relevant ZFS datasets should be encrypted. ATM Veles supports only passwords encryption.
* ZFS automount (that is, `zfs mount -a` or equivalents) should be preferably completely disabled.
  If you do use it - you're heavily encouraged to also use `--all_datasets` option for properties
  verification (see below) to make sure an attacker cannot modify mount paths-related properties
  without Veles noticing.

### Recovery

You should expect that **you'll do this at least once (likely more) during setup / integration
process**, so **make sure you fully understand how to do it**.

This assumes Veles is enabled already, but `load` or `verify` fails and the fallback doesn't work.

There might be some variations depending on your setup, but the process will likely look roughly
as follows:

* Reboot and enter BIOS.
* Enter Administrator password (you did password-protect BIOS after Secure Boot setup, right?)
* Disable Secure Boot.
* Enable booting from USB / CD / network / whatever you use for recovery.
* Save the changes in BIOS.
* Reboot into recovery of your choice.
* Import the necessary ZFS pools, enter encryption passwords manually, mount the necessary
  datasets.
* Modify the configs / integration as necessary to correct the problem.
* If re-running `veles setup` is needed to correct the problem - note that you won't be able to
  use PCR 7 at this point because Secure Boot is disabled, so the content of PCR 7 will be
  different than during the boot with Secure Boot enabled. You might need to temporarily exclude
  PCR 7 from the list of measured PCRs.
* Save the necessary changes and reboot.
* Check that the problem was corrected / the boot now works.

If the problem is fixed - you can re-enable Secure Boot:

* Reboot into BIOS.
* Enter Administrator password.
* Enable Secure Boot.
* Disable booting from removable media.
* Save the changes and exit BIOS.
* Boot into the system.
* Re-run `veles setup` - now including PCR 7.
* Reboot and check everything works.

If you have Secure Boot-compatible recovery image - this process might be simplified, but having
such an image available opens its own can of worms and I'm not covering this approach here.

See also "Debugging tips" below for some extra advice.

## Concepts

The following concepts are important to understand before you start integrating Veles into your
system.

### ZFS properties verification

Veles computes the hash of selected ZFS properties during `setup` phase and then verifies at each
boot this hash matches the actual value observed at the boot time.

This ensures that the "overall structure" of the relevant datasets is correct and the datasets
with expected names are present, but cannot serve as a guarantee that the datasets are
authentic - ZFS doesn't offer properties encryption, so it's trivial to clone / fake the expected
properties by an attacker.

The choice of what datasets to include in this check is a trade-off between security and
flexibility. By default only the mounted datasets are included, but if `--all_datasets` option is
specified in `setup` then all datasets are included. This increases security (= now the attacker
cannot add a new dataset with a mount point that shadows some existing dataset) but any change
to the datasets in the pool (such as adding or renaming any dataset - even the ones not used for
the boot) will cause properties verification failure and will prevent the system from booting.

### Passwords unsealing

The passwords necessary to decrypt the datasets are sealed in TPM using the specified PCRs + ZFS
properties verification hash that is computed as described above. These passwords are then
unsealed during boot if PCRs content + ZFS properties hash match the expected values and are
loaded into ZFS + root user keyring so that subsequent Veles calls for datasets authentication
have access to these.

### ZFS datasets authentication

Because just properties verification is not sufficient for making sure the datasets are
authentic / were not replaced by an attacker, Veles also performs datasets authentication step.
It is based on storing root-only readable salted hash of an encryption password on the dataset
that is encrypted with that password together with hashed properties of this dataset. Once
datasets are mounted, Veles reads this information from each dataset and verifies it matches
the expected values that are computed from the actual encryption password (unsealed from TPM)
and actual dataset properties.

This step by necessity can run only on those datasets that are currently mounted, therefore it
might be necessary to repeat Veles verification calls several times throughout the boot
process - each time when extra datasets are mounted but before the content from these datasets
is used to continue the boot.

## Detailed usage

### `veles setup`

Conceptually this call consists of two main steps:

* Preparation for "ZFS datasets authentication": computing and storing on each dataset the
  information necessary for the subsequent authentication of this dataset.
* Preparation for "ZFS properties verification" and "passwords unsealing" stages: computing
  properties verification hash and sealing ZFS encryption passwords in TPM using this hash +
  other PCRs values.

The second step can be skipped if only authentication setup is necessary by specifying TPM
device name as `none`. See also the section "Datasets authentication without TPM" below.

For preparing datasets authentication, by default all currently mounted datasets are used,
but some of these mounted datasets can be skipped with `--exclude` flag.

For "ZFS properties verification" stage you can control which datasets will be included as
follows:

* `--all_datasets` flag is NOT specified: the same set of datasets as for "ZFS datasets
  authentication" setup above will be used.
* `--all_datasets` flag is specified: all datasets are included regardless of their mount
  status or the values in `--exclude` flag.

If the setup is successful, Veles will write the verification config in JSON format that
will be used for all subsequent operations.

Note that mount paths during `initrd` stage (when `load` and `verify` Veles calls will be
done) might be different from the paths that `setup` call sees. For example, it's typical
for boot implementations to mount the datasets in a separate directory tree and then perform
chroot into that directory. If that's how your boot setup works - **you need to adjust
veles.json config** after `setup` finishes to specify the actual mounts that Veles will
see at `initrd` stage.

You also need to select the set of PCRs to measure that ensures the authenticated boot path
all the way to Veles call. Consult
[Linux TPM PCR Registry](https://uapi-group.org/specifications/specs/linux_tpm_pcr_registry/)
for more info but TL;DR: you probably want to use PCR 7 for verifying Secure Boot, some
higher-number / unused PCR for storing the hash of ZFS datasets properties (the default value
in Veles settings is PCR 15), preferably - also the PCR extended by bootloader that indicates
which system was booted and optionally any other PCRs in-between that are either unused or set
to stable values.

By default the `--no_fallback` option is not set so if the unsealing fails - you can still
boot by entering passwords manually. Note, however, that this is also exactly how the
"evil maid" attack scenario will look like, that is - if somebody resets Secure Boot and
replaces any of bootloader / kernel / initrd components with malicious version that is going
to send the passwords to the attacker - by entering the passwords manually you've just made
their attack successful. Therefore, if you leave the fallback enabled - **make sure you
understand why unsealing failed** before proceeding with entering passwords manually.

Adjusting KDF options is optional. I don't expect that in most scenarios brute-forcing the
files with passwords hashes on encrypted datasets is an attack vector to worry about. If an
attacker can already read root-only readable files on encrypted dataset - in most cases
getting plain-text password won't give an attacker extra privileges (you're not reusing the
same password for different purposes / systems, right?) However, if this is the scenario you
worry about and your PC is powerful enough to handle higher settings that are set by default
(which are tailored to quite slow PCs) - you can try increasing these settings. My
recommendation is to increase `--kdf_memory` only and leave the other settings alone, but if
you know what you're doing - it's up to you.

### `veles load`

This call should happen early in boot process - typically in initrd stage of the boot.

In this call Veles will perform "ZFS properties verification" + "Passwords unsealing" steps.
This call should happen after all the relevant ZFS pools are imported but before any ZFS
datasets on them are mounted (as encryption keys won't be available for mounting before this
call completes).

During this call Veles does the following:

* Computes the list of all security-relevant properties of all datasets according to its
  config.
* Uses the hash of this list + the values of specified PCRs to unseal your encryption
  passwords from TPM and load them into ZFS via `zfs load-key`.
* Puts these passwords into current user keyring so that `verify` stages later have access
  to them.

If any of the properties of any ZFS datasets won't match the expected value, or the values of
PCRs won't match the expected values - the unsealing will fail. Then, depending on the options
specified, Veles will take one of the following actions:

* Unless `--no_fallback` option is set: asks the user to enter passwords manually, if the
  passwords are entered successfully (as indicated by exit code of `zfs load-key`) - store
  the passwords in keyring and exit cleanly.
* If `--debug` option is set (**use this for debug only**): print error message but exit
  cleanly, thus allowing the boot to continue. The boot will likely fail, though, as ZFS
  encryption passwords were not loaded.
* If `--no_poweroff` option is set - exit with error code, thus stopping the boot.
* Otherwise it will shutdown or reboot the machine, and failing to do that - will return error
  code so that the boot is stopped.

Unless you're using systemd at initrd stage (and specified `--systemd_ask_password` option)
or disable `--no_fallback` option you'll have to satisfy two contradictory requirements:

* Veles should be attached to the console to ask the user to enter the passwords.
* Veles should not be attached to the console to prevent attacks like terminating it after
  the passwords are unsealed (might or might not be a problem depending on how the boot
  is set up).

I recommend using systemd, setting up Veles calls as services and specifying
`--systemd_ask_password` option.

### `veles verify`

This call performs "ZFS datasets authentication" step. It should happen after all the datasets
relevant for authentication were mounted but before any files are executed from these datasets.

During this call Veles does the following:

* Gets ZFS passwords from the user keyring and removes them from keyring, unless `--keep_keys`
  option is set.
* Reads salted hashes from all datasets specified in its config and confirms they match these
  passwords.
* Verifies the hash of properties for each dataset matches the hashed value on disk.
* (Unless TPM device is `none` in config) Extends the specified PCR with the hashes of all
  authenticated datasets.

If any of these steps fail - Veles will do one of the following actions:

* If `--debug` option is set (**use this for debug only**): print error message but exit cleanly,
  thus allowing the boot to continue.
* If `--no_poweroff` option is set - exit with error code, thus stopping the boot.
* Otherwise it will try to unmount all ZFS datasets, unload all the encryption keys and then
  shutdown or reboot the machine, and failing to do that - will return error code so that the
  boot sequence is interrupted.

For this stage to work, `load` call should have completed successfully (or the passwords should
have been loaded into user keyring via other means) + Veles should be able to access the
passwords in the user keyring.

By default systemd units use isolated keyrings, so if you run Veles as systemd unit (which is the
recommended setup) - you should specify `KeyringMode = inherit` in unit settings both for `load`
and `verify` units or have some equivalent setup that allows keyring sharing between `load` and
`verify` units.

You can repeat `verify` calls multiple times, each with a different config - see `nixos` example
where the first call is done at initrd stage and verifies the initial set of mounts that is used
in early boot, and then the second call is done after chroot in stage 2 to verify the rest of
datasets. Note that for multiple calls all but the last call should have the option `--keep_keys`
specified. You'll also need to make sure that each call has the corresponding config, that is -
includes only those datasets that should be authenticated at this particular call. You should
exclude already verified datasets with `--exclude` option.

### Password input

In `setup` (and, if fallback is enabled, in `load`) modes Veles will ask for encryption passwords
for ZFS. These passwords will be asked either directly in console or via systemd interface
(if `--systemd_ask_password` option is specified). For both of these input methods the passwords
will be verified via `zfs load-key` call and then loaded into user keyring.

## Initrd integration

In most typical Linux boot scenarios, for `load` and initial `verify` call, Veles binary has to
reside in the [initrd image](https://en.wikipedia.org/wiki/Initial_ramdisk).

Veles binary is reasonably small and should depend only on `libc` - which very likely is present
in your initrd image already.

Use your distribution-specific instructions / process to add Veles to the initrd image. The module
demonstrating Veles integration into NixOS boot process is provided in `nixos` directory.

Several extra notes:

* The verification config should be embedded into `initrd` together with Veles binary as well and
  Veles should be called with the path to that config specified.
* Initrd image should be signed / checksummed as part of Secure Boot setup and this signature /
  checksum should be verified on each boot by bootloader.

## Datasets authentication without TPM

If you don't want to use TPM to store the passwords / prefer to enter them manually, but still
are concerned about "filesystem replacement" attacks - you can skip the `load` stage and call
Veles in `verify` mode only.

To make it work you'll need to make sure that your passwords for the corresponding ZFS encryption
roots are loaded into user keyring with the name `zfs-<encryption root name>` before calling
`veles verify`. The rest should be similar to the setup described above.

## Development

If you have Nix installed - just use `nix-build` or `nix-shell` in project directory. Otherwise
you'll need to install the necessary dependencies using your distribution-specific process, but
their list is small, so it should be easy to replicate the build / test / packaging process, if
necessary.

### Dependencies

See `buildInputs` in `shell.nix` for the list of build dependencies and `nativeBuildInputs` for
test dependencies.

### Building

For the manual build you can use `zig build -Doptimize=Debug` for development / debugging and
`zig build --release=small` for release in the project directory.

The code was tested with Zig 0.15.2 and given my (limited) experience with Zig - the libraries
APIs are still changing quite often, so the code might not compile with other versions.

### Testing

If you do any changes to the code - I highly recommend re-running the tests with
`bats tests/veles.bats`

Note that the tests use patched version of `swtpm` that has some extra features necessary for the
tests. If you use `shell.nix` you should already be all set, though.

### Packaging

The built binary is self-sufficient and depends only on `libc` => just copy it to target location.

## Debugging tips

All the tips below are for debugging only and **should be reverted before the actual deployment**.

### General

* Use PCR 16 as `--extend` PCR that Veles writes into. This PCR can be reset (e.g. by calling
  `tpm2_pcrreset 16`) => it's easy to perform multiple rounds of `setup` + `load` + `verify`
  experiments without rebooting.
* Skip PCR 7 from the list of measured PCRs when you're debugging Secure Boot setup. This will
  allow the system to boot even with disabled Secure Boot or if its configuration is changed.
* Use `--debug` option in all Veles calls. This option will both print some extra debugging
  information (which might be useful for troubleshooting) and will turn off the power-off /
  reboot functionality in the case of loading or verification failures.
* Use `--check_only` option in `load` call if you're running it for datasets which have the
  keys loaded already.
* Use `--exclude` option in `verify` call to discard the other mounted ZFS datasets that otherwise
  would cause verification failures.
* If you want to get closer to the actual deployment behavior but still don't want to reboot the
  system in the case of failures, both `load` and `verify` accept `--no_poweroff` option.
* Use `tpm2-tools` for inspecting the state of PCRs and TPM. Some of the useful commands:
  `tpm2_pcrread`, `tpm2_pcrreset 16`, `tpm2_getcap handles-persistent`,
  `tpm2_getcap properties-variable`, `tpm2_getcap algorithms`.

### TPM lockout

TPMs typically have dictionary attack lookout functionality enabled that will block further access
to TPM for some time if too many failed auth attempts are done. Each failed unseal call will count.

You might need to temporarily relax the limits of DA lockout while you're debugging - see
`tpm2_dictionarylockout` tool.

### Emergency access

For debugging some types of failures it might be beneficial to enable an emergency access into
initrd shell. For NixOS in systemd initrd mode this can be done with
`boot.initrd.systemd.emergencyAccess = true` setting.
