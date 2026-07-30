# Contributing to Haven Crypto

Thank you for your interest. Because this is cryptographic code that real people's privacy
depends on, contributions are held to a high bar.

Please also follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Ground rules
- **No hand-rolled cryptography.** Build on vetted, well-reviewed primitives only.
- **Known-answer tests (KATs) must stay green.** Any change touching crypto must keep the
  test vectors passing - see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the module map,
  and run `cargo test --release` (172 tests) before opening a PR.
- **`unsafe` is justified or absent.** Every `unsafe` block needs a documented rationale.
- **Reproducibility is preserved.** Changes must not break the reproducible build.

## Workflow
1. Open an issue describing the change before large work.
2. `cargo fmt`, `cargo clippy -- -D warnings`, `cargo test`, and `cargo audit` must pass.
3. Sign off your commits (`git commit -s`, adding a `Signed-off-by` trailer per the
   [Developer Certificate of Origin](https://developercertificate.org/)) - GPG-signing is welcome
   too but not required.

## License
By contributing you agree your contributions are licensed under
[AGPL-3.0-or-later](LICENSE).

This project also carries an additional permission under section 7 of that license, which is what makes
distribution through application distribution platforms possible at all — see
[ADDITIONAL-PERMISSIONS.md](ADDITIONAL-PERMISSIONS.md). A permission of that kind reaches only the
copyright it was granted for, so **please extend the same permission to your own contribution.** Adding
this trailer beside your `Signed-off-by` is enough:

```
Additional-Permission: AGPL-3.0-or-later section 7, application distribution platforms, per ADDITIONAL-PERMISSIONS.md
```

You are not required to. A contribution without it is welcome and is licensed under the AGPL as normal —
but a build for an application distribution platform cannot then include it, so we may have to keep it
out of that build rather than out of the project. Saying so plainly here is better than discovering it
later.
