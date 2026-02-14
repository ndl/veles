# Security

## TPMs overview

The following text assumes some familiarity with TPMs and related concepts.

For developer-level tutorials I can recommend
[TPM-JS](https://google.github.io/tpm-js/index.html#pg_welcome) and
[tpm2dev](https://github.com/tpm2dev/tpm.dev.tutorials/blob/master/Intro/README.md).

For user-level tutorials I don't have any specific recommendations but I'm pretty sure one
can find smth on the Internet.

For a short overview of security issues with TPMs one can check
[this blog post](https://sigma-star.at/blog/2026/01/tpm-on-embedded-systems-pitfalls-and-caveats/)
that focuses on embedded TPMs, but many conclusions are relevant more widely.

TL;DR: while TPMs are capable of providing some extra security, they do have multiple weaknesses /
attack vectors. Therefore, if the choice is between "do not encrypt your data at all" and
"encrypt it with the keys stored in TPM" - the second choice likely is more secure. However, if
the choice is between "encrypt your data with a (strong) password entered each time when the data
is accessed" and "encrypt it with the keys stored in TPM" - in most cases the first choice is
likely more secure.

Note that while not the main intended use case, Veles can also be used without TPMs / for ZFS
datasets authentication only - see "Datasets authentication without TPM" in
[Integration](Integration.md).

## Target use case and assumptions

The main use case for Veles is to allow the system to boot from encrypted ZFS datasets without
the user entering the passwords for these datasets on each boot, while protecting these
passwords from not very sophisticated attacker who has full physical access to the system.

To implement this use case, Veles performs the following two main tasks on each boot:

* Load passwords for ZFS datasets from TPM if the boot environment is in the expected state.
* Authenticate the mounted ZFS datasets before the boot process is transfered to these datasets.

In order to perform these tasks securely, Veles requires a lot of assumptions to be met in other
parts of the system. See [Integration](Integration.md) for general overview but here's (partial)
list of these assumptions that are relevant for security:

* The boot path from system reset / power-on to Veles call is fully trusted and measured. This
  means that no software or hardware that is unintended by the user / that might interfere with
  Veles operation controls the boot at any point, or if that does happen - this is detectable by
  the changes in TPM PCRs that store the hashes or signatures of the executed boot components. If
  this assumption is broken - the attacker can either emulate the process Veles uses to unseal
  the keys from TPM or mess with the execution environment to steal these keys once Veles unseals
  them.
* The integration is done in a way that ensures the `verify` call cannot be skipped during the
  boot. If this assumption is broken - "filesystem replacement" attack becomes possible.
* If the system has any other boot paths besides the one that calls Veles (e.g. dual-boot into
  other OS), extra steps need to be taken to modify TPM state and avoid exposing the passwords -
  see [MultiBoot](MultiBoot.md). If this assumption is broken - the attacker with access to TPM
  under the other OS can unseal the keys by emulating the process Veles uses.
* ZFS implementation cannot be tricked into re-reading / re-mounting the datasets after they're
  authenticated by Veles. If this assumption is broken - "filesystem replacement" attack
  becomes possible.
* System configuration doesn't mount any extra datasets (such as by having ZFS auto-mount using
  mount points stored in ZFS dataset properties) without controlling their mount points after
  Veles `verify` call is completed. If this assumption is broken - "filesystem replacement"
  attack becomes possible.

## In scope attacks

Based on "Target use case and assumptions" above, here are the attacks that Veles intends to (fully
or partially) protect from.

### Non-trusted boot

As long as trusted boot chain (BIOS / UEFI -> bootloader -> Linux kernel -> initrd environment +
their TPM measurements) works as intended, Veles should not unseal the passwords in the untrusted
environment. That is, if somebody clears CMOS / resets BIOS state / disables Secure Boot in any
other way and then tries to boot the system - passwords unsealing should fail so the attacker
won't get access to them.

### Filesystem replacement

See the description in
[this write-up](https://oddlama.org/blog/bypassing-disk-encryption-with-tpm2-unlock/) and also
[this issue](https://github.com/jricks92/zfs-tpm2-unlock/issues/1).

Veles tries to evade this attack by authenticating the mounted encrypted datasets.

This authentication is done by verifying the salted hash file of the encryption password that is
written to this dataset during Veles `setup` stage. In principle, absent bugs in ZFS
implementation, this should ensure that we're seeing the "authentic" dataset - because the only
ways to present the correct contents of this file to Veles is to either read it from the encrypted
dataset (and for accessing this file on the encrypted dataset, one should either know the
encryption password - which is exactly what we're protecting - or have root-level dataset access
already via other means) or to compute it and write it to "fake / replacement" dataset (and that
also requires knowing the encryption password).

### Datasets swapping

This is a variant of "filesystem replacement" attack where the attacker doesn't try to create fake
datasets but swaps the existing datasets - which is possible to do because ZFS doesn't encrypt
datasets properties. This might make sense for an attacker to do if they already have control over
one of the encrypted datasets (for example, this is their home dataset or another dataset where
they can control the files). They can perform privileges escalation then by writing the files on
the dataset they control (like `sbin/init`) and then swap the properties of this dataset with the
dataset used for the boot.

Veles mitigates this attack by storing the hash of relevant datasets properties on the encrypted
dataset as a root-only accessible file and verifies these during datasets authentication.

### [Evil maid](https://en.wikipedia.org/wiki/Evil_maid_attack)

Here I mean it only in the "narrow sense", that is - replacing some parts of the system or the
system completely to try stealing the passwords.

Because during normal operation the passwords protected by Veles should not be entered by the
user - this attack should not be possible, although see the corresponding "out of scope" section
below.

### Disks / system forensic analysis

As long as the setup and integration is done correctly, there should be no extra information in
non-encrypted disk areas that aids in recovering ZFS passwords or leaks other sensitive
information about encrypted ZFS datasets, so the setup should be as protected (or as vulnerable)
as "normal" ZFS encrypted setup.

### Passive [Man-in-the-Middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)

For intercepting TPM traffic specifically, this attack should be prevented due to Veles using
parameters encryption when unsealing the keys, that is - at `load` stage the passwords are sent
to Veles in encrypted form with the key that was dynamically generated for this specific
transaction and communicated with TPM using eithe RSA encryption or
[ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman). Therefire, it should
not be possible for an attacker to get the passwords. See also
[CPU to TPM Bus Protection Guidance – Passive Attack Mitigations, v1.0](https://trustedcomputinggroup.org/wp-content/uploads/TCG_CPU_TPM_Bus_Protection_Guidance_Passive_Attack_Mitigation_8May23-3.pdf)
document for details.

## Out of scope attacks

The attacks below are (some of the) known attacks that are likely to be successful on
Veles-protected system but are out-of-scope. That is - Veles is currently not designed (and
likely will never be designed) to protect the system from these attacks.

### Setup stage

Veles assumes the `setup` is done in trusted environment and no mitigations from any attacks
at this stage are employed. Only `load` and `verify` stages should be considered protected from
the attacks described above.

### Weak setup or integration

Any errors in setup or integration, such as (but not limited to):

* Measuring wrong / incomplete set of PCRs for the intended use case.
* Authenticating wrong / incomplete set of ZFS datasets.
* Having non-encrypted ZFS datasets participating in boot.
* Having auto-mounted ZFS datasets that are not authenticated by Veles.
* Having weak passwords on encrypted ZFS datasets.
* Any issues / weaknesses in Security Boot setup.
* Being able to bypass `verify` calls.
* Being able to drop into emergency shell during boot.

... and much more are "out of scope".

Note this includes any setup that allows the attacker to interact with Veles during `load` or
`verify` calls from console. There's some rudimentary hardening (e.g. Veles ignores SIGINT signals
in `verify`) but definitely not enough to expose it to the attacker "directly". This is one of the
reasons that systemd integration is recommended, as then Veles can run as a `onetime` service that
is not interacting with the user directly in any way.

### Non-trusted boot

Any vulnerabilities in BIOS / UEFI, Secure Boot, bootloader, Linux or TPM that compromise correct
TPM measurements functionality are "out of scope".

### Filesystem replacement

The authentication scheme used by Veles won't work if there's any way for an attacker to prepare
"partially fake" encrypted dataset that has the expected encrypted master key in its metadata, the
relevant blocks that store the encrypted metadata - but other data blocks are replaced with
attacker's content and are not encrypted. Given ZFS implementation uses hierarchical checksums
(including HMACs in encrypted datasets case) to verify the contents it reads, this type of attack
shouldn't be possible, and would be both a significant security and data correctnesss bug in
ZFS implementation. However I'm not sure how extensively ZFS encryption implementation was audited
to guarantee the absence of any bugs like this.

Any issues in ZFS filesystem implementation that can lead to the breach of Veles authentication
scheme are "out of scope" from Veles target use case.

### [Evil maid](https://en.wikipedia.org/wiki/Evil_maid_attack)

By default the `--no_fallback` option is not set for either `load` or `verify` stages, so if
the unsealing ov verification fails - you can still boot by entering passwords manually. Note,
however, that this is also exactly how the "evil maid" attack scenario will look like, that
is - if somebody resets Secure Boot and replaces any of bootloader / kernel / initrd components
with malicious version that is going to send the passwords to the attacker - by entering the
passwords manually you've just made their attack successful. Therefore, if you leave the
fallback enabled and see (seemingly) Veles password prompt - **make sure you understand why
unsealing or verification failed** and **make sure that the current environment is not
attacker-controlled** before entering the passwords.

Also note that we're discussing here boot-time ZFS datasets encryption only and Veles does
nothing to protect you from "evil maid" attacks on passwords that are not managed by Veles and
entered by the user normally, like login passwords.

### [Side channel](https://en.wikipedia.org/wiki/Side-channel_attack)

Currently Veles doesn't have any specific measures against this class of attacks. The main
vulnerable pieces are likely ECC and RSA-related computations (might be used for recovering the
exchange key with TPM used for unsealing and help with passive MitM attack) and operations on ZFS
passwords (e.g. their hashing).

In both cases Veles uses standard Zig library implementations of these (e.g. see
[Sha256](https://ziglang.org/documentation/0.15.2/std/#std.crypto.sha2.Sha256) and
[P384](https://ziglang.org/documentation/0.15.2/std/#std.crypto.ecc.P384)). I haven't analysed
these in detail + lack the knowledge / skills to perform this analysis anyway, but I don't
believe they're side-channel resistant ATM.

### Passive [Man-in-the-Middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack)

All the passive attacks on the components other than TPM itself (such as RAM, CPU, any buses etc)
are "out of scope".

### Active TPM attacks

That is, active [Man-in-the-Middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) or,
really, any other type of attack that actively messes with TPM such as desolder-and-move,
voltage-based attacks, destructive TPM contents analysis, firmware or BIOS-targeted attacks, etc.

If anyone capable of performing these types of attacks targets you - you're likely screwed anyway.
But for any avoidance of doubt - Veles doesn't provide any protections in any of these
(or similar) scenarios and they're "out of scope".

### Input attacks

Any attacks that provide malicious input to Veles - such as through the console, the output of the
tools Veles calls, the hijacked TPM interface, modified config or on-disk hash files, etc - are
also "out of scope". I don't consider them important enough to address as if any of these
channels is taken over by an attacker, this means either the boot path, the system itself or TPM
was successfully hijacked and there's nothing left for Veles to protect.

### Kernel attacks

Any attacks on kernel, such as gaining access to kernel keyring or to Veles inputs / outputs via
kernel interfaces, are "out of scope".
