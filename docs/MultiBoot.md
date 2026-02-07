# Multi-boot

## General considerations

When doing any form of multi-boot one extra attack scenario is unsealing the passwords from TPM
on another booted system.

That is, if the other system is either compromised or lets someone access TPM due to its security
settings, it will be possible to unseal the passwords by extending the right PCRs with the values
expected by the policy stored in TPM during Veles `setup` call.

To prevent this attack one should make sure that:

* There's at least one PCR that is extended to a different value depending on which OS is booted.
  Preferably this should be done by the bootloader to decrease the attack surface through the
  other system. The value itself doesn't really matter and can be either fixed string, the
  signature of the booted OS or any other value that is not going to change frequently but is
  indicative of which OS is booting.
* This PCR is included into the list of PCRs measured by Veles in `setup` call.

## Windows-specific notes

When using Secure Boot on the system that can boot into Windows, typically one would enroll both
their own keys and Microsoft keys into Secure Boot - otherwise Windows boot won't be possible.

However, this introduces an extra attack vector as there are regularly discovered vulnerabilities
in various bootloaders / tools that are signed with Microsoft keys.

To protect from these compromised bootloaders / tools, Secure Boot contains a Forbidden Signature
Database (DBX) that needs to be updated regularly, otherwise your system becomes vulnerable.

However, each update of DBX changes the hash of Secure Boot that's stored in PCR 7, which makes
the passwords protected by this PCR in TPM not possible to unseal anymore.

Depending on your use case, you can either:

* Fix the setup manually on each update. That is, the sequence of events might be as follows:
  * DBX update is applied.
  * On the next reboot the system fails to unseal the passwords due to PCR 7 content change.
  * You enter passwords manually to boot successfully.
  * You re-run `setup` that now sees changed PCR 7 content and re-seals the passwords with new
    PCR policy.
* Implement some automation that calls `setup` after each DBX update is applied in "unattended"
  mode. That won't be trivial due to several issues:
  * Windows might apply this update automatically while you're booted into Windows, and then
    you're back to the previous case.
  * Veles needs access to ZFS passwords during setup. In principle they can be provided via the
    keyring but then you need another secure storage mechanism to read them from to load into
    keyring.
  * You need to know the expected value of PCR 7 after the update. I don't know how exactly this
    value is computed by UEFI and whether this process is even standardized. Anyhow, this is
    currently not implemented in Veles.
