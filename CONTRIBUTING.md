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
