# openmls cross-version proof

Tests that crypto-core on the pinned openmls revision (this checkout) and crypto-core on openmls 0.9.2 (revision
`d006259`, the last one on that release) work on each other's state and in one group.

The two cannot be linked into one binary: they pin incompatible versions of shared dependencies. So `previous/` builds
crypto-core at `d006259` into a small driver that runs one operation per call, a JSON request on stdin and a JSON answer
on stdout, with byte strings as hex. `current/` runs the same operations on this checkout in process, and its tests hand
state and messages between the two exactly as a device would: state from storage, messages from the wire.

`previous/Cargo.lock` is crypto-core's own lockfile at `d006259` plus the driver, so the previous side builds the same
dependency versions that revision shipped with, openmls 0.9.2 included. A git dependency does not bring its lockfile, so
the driver also pins `openmls = "=0.9.2"`.

Neither crate is part of the crypto-core build: a second openmls in the root lockfile would bring the previous release's
dependency advisories into `cargo audit`, and the git dependency would fail the manifest-purity guard.

## Running

```sh
cd tools/openmls-cross-version/current
cargo test
```

The first test to need the driver builds it with `cargo build --locked` into the test's target
directory.

## What the tests show

- `state_the_previous_release_wrote_continues_under_this_one`: a group, a member's state with a message
  still unread, and an identity bundle holding an unused key package, all written by 0.9.2, continue
  under this checkout. Both releases read the same group metadata from that state.
- `members_on_both_releases_share_one_group` and `members_on_both_releases_share_one_mimi_group`:
  Welcome, application messages, commits and removals pass between members on the two releases in both
  directions. On the MIMI lane only the group's creator adds members: on either release a member who
  joined by Welcome sends Welcomes without the ratchet tree.
- `state_this_release_wrote_continues_under_the_previous_one`: a group state this checkout wrote loads under 0.9.2 and
  goes on reading and sending, on both lanes and after commits, so a device can move back.
- `a_hub_on_this_release_reads_a_key_package_the_previous_release_built`: the gate and the KeyPackage reference a hub takes
  for an Add accept a KeyPackage built on 0.9.2.
- `a_pending_commit_the_previous_release_stored_confirms_under_this_one` and
  `..._abandons_under_this_one`: a pending commit 0.9.2 staged and stored before sending is confirmed by
  this checkout on acceptance, on a native group and on MIMI groups sending handshakes in the clear and
  privately, and the successor works with the other members. Abandoning it gives a predecessor-epoch
  state that goes on working, byte for byte the stored predecessor for a commit sent in the clear.
- `a_corrupted_previous_state_is_refused`: the negative control. A 0.9.2 state with its group-state tag
  corrupted is refused, so the state rows read what is stored rather than accepting anything.
