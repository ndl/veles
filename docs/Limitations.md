# Limitations

## Security and reliability

As mentioned in README.md, not only there was no audit / verification of this implementation -
but there are also good reasons to be highly sceptical of both the security and reliability
of this implementation.

This should be considered a major limitation - and, in fact, a deal-breaker / show-stopper
for any serious / non-hobbyist use.

## ZFS

There are several limitations of ZFS design / implementation that result in extra pain and
complexity in Veles implementation and operation.

One such limitation is that ZFS doesn't provide encrypted properties. This means that attacker
can read and modify any property of any dataset (including for encrypted datasets) without
knowing the password.

This means we cannot trust any property we're reading from ZFS and have to store some content
for verification / authentication on the encrypted dataset itself.

Another limitation is the fact that ZFS doesn't provide an API to get the key material for the
encryption roots. That is, there's nothing similar to `cryptsetup luksDump` functionality.

See also the following (unresolved) issues:

* [#12649](https://github.com/openzfs/zfs/issues/12649).
* [#15952](https://github.com/openzfs/zfs/issues/15952).

Without access to key material, we cannot be sure that currently present datasets are really
the ones that we should be mounting.

All the work-arounds to these limitations I can think of have significant downsides.

### Store secrets on encrypted datasets

That is, store the file on each encrypted dataset that contains some secret value that is
impossible for an attacker to guess and, therefore, replicate on their "fake" dataset.

This is the current work-around that Veles implements. It gets the job done as a way of
authenticating the datasets but has multiple disadvantages arising from the fact that we
need to separate passwords unsealing from datasets authentication. This is because we need
to unseal keys first to be able to mount the datasets and only then can perform authentication.

This opens the door to various weaknesses / attacks because the system is briefly in a state
when all the passwords are loaded and datasets are mounted, but the datasets are not yet verified
and might be attacker-controlled.

For example, any Veles integration error that leads to boot process reading or executing any
files from these mounted datasets in this time window can potentially lead to compromise.

This also complicates Veles design + implementation + usage because instead of a single call
that does both passwords loading and verification we need to perform two (or more) calls that
are carefully orchestrated to be done exactly at the right times.

This also has a disadvantage of requiring Veles to store special file per each dataset (we cannot
store this content in properties as the properties are not encrypted) and any modification or
removal of this file breaks the authentication process and renders the system unbootable.

### Read key material directly

In principle, the format of ZFS filesystem is known => it should be possible to read key material
out of it ourselves without using ZFS API.

I don't consider this an acceptable alternative for a number of reasons:

* This is a non-trivial amount of work that requires good understanding of ZFS internals (which I
  definitely lack).
* Any change in ZFS format might break this code and render the system unbootable or open it up
  for attacks.
* Even if this code works for "normal" filesystems, it's very hard to guarantee it uses the same
  error control / data integrity verification / responds to unexpected filesystem format exactly
  as the "official" ZFS implementation does. And any discrepancy here can open us to
  "filesystem replacement" type of attack where an attacker would craft a fake filesystem that
  reads one version of key material when using this "custom" reading code and another version when
  using the "official" implementation. And even if both implementations can be made to match each
  other at some point, there's no guarantee they won't diverge afterwards.
* This doesn't prevent "datasets swapping" attack where two datasets are exchanged, as there's no
  way to authenticate datasets properties with this key material.

## TPM

Veles interacts with TPMs directly via kernel interface.

The advantages of this approach are:

* Veles doesn't depend on (relatively large) "standard" TPM libraries + their transitive
  dependencies => we can keep the overall initrd image size smaller.
* There's no need to do C interop between these TPM libraries and Zig.
* Veles can do exactly the calls and with exact parameters that are necessary to get its job done
  (some TPM libraries do quite some work behind the scenes which might or might not be desirable
  depending on the use case).
* I've got to understand TPM functionality much better than if I were to use an existing
  library :-)

There are also disadvantages, though:

* Given I didn't have experience working with TPMs before and haven't done significant testing,
  it's quite likely I've implemented some things incorrectly, which might result in quite severe
  consequences.
* The compatibility of this custom implementation is almost surely worse than of the "standard"
  TPM libraries => it probably won't work for some TPMs which the "standard" TPM libraries would
  have handled.

Personally I'm fine with these disadvantages and don't plan to change the way the things are
implemented, but you should consider how critical these are for your use case and decide
accordingly.
