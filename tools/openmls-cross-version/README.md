# openmls cross-version proof

Tests that crypto-core on openmls 0.9.2 (this checkout) and crypto-core on openmls 0.8.1 (revision
`4b02ef2`, the last one on that release) work on each other's state and in one group.

The two releases cannot be linked into one binary: their crypto providers pin incompatible versions
of a shared dependency (`hax-lib`). So `previous/` builds crypto-core at `4b02ef2` into a small driver
that runs one operation per call, a JSON request on stdin and a JSON answer on stdout, with byte strings
as hex. `current/` runs the same operations on this checkout in process, and its tests hand state and
messages between the two exactly as a device would: state from storage, messages from the wire.

`previous/Cargo.lock` is crypto-core's own lockfile at `4b02ef2` plus the driver, so the previous side
builds the same dependency versions that revision shipped with, openmls 0.8.1 included. A git
dependency does not bring its lockfile, so the driver also pins `openmls = "=0.8.1"`.

Neither crate is part of the crypto-core build: a second openmls in the root lockfile would bring the
previous release's dependency advisories into `cargo audit`, and the git dependency would fail the
manifest-purity guard.

## Running

```sh
cd tools/openmls-cross-version/current
cargo test
```

The first test to need the driver builds it with `cargo build --locked` into the test's target
directory.

## What the tests show

- `state_the_previous_release_wrote_continues_under_this_one`: a group, a member's state with a message
  still unread, and an identity bundle holding an unused key package, all written by 0.8.1, continue
  under 0.9.2. Both releases read the same group metadata from that state.
- `members_on_both_releases_share_one_group` and `members_on_both_releases_share_one_mimi_group`:
  Welcome, application messages, commits and removals pass between members on the two releases in both
  directions. On the MIMI lane only the group's creator adds members: on either release a member who
  joined by Welcome sends Welcomes without the ratchet tree.
- `state_this_release_wrote_loads_under_the_previous_one_only_with_the_old_field_name`: 0.8.1 cannot
  load a group state 0.9.2 wrote. 0.9.2 stores the join configuration's retention setting as
  `past_epoch_deletion_policy`, and 0.8.1 reads only `max_past_epochs`. With that one field under its
  old name, 0.8.1 loads the state and goes on reading and sending, on both lanes and after commits.
- `a_pending_commit_the_previous_release_stored_confirms_under_this_one` and
  `..._abandons_under_this_one`: a pending commit 0.8.1 staged and stored before sending is confirmed by
  0.9.2 on acceptance, on a native group and on MIMI groups sending handshakes in the clear and
  privately, and the successor works with the other members. Abandoning it gives a predecessor-epoch
  state that goes on working, byte for byte the stored predecessor for a commit sent in the clear.
- `a_corrupted_previous_state_is_refused`: the negative control. A 0.8.1 state with its group-state tag
  corrupted is refused, so the state rows read what is stored rather than accepting anything.
