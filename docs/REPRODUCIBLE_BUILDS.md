# Reproducible Builds - Haven Crypto

## Status: Stage 1 verified - WASM rlib, byte-identical
This crate builds as a plain `rlib` for the `wasm32-unknown-unknown` target (there is no
`wasm-bindgen` post-processing here - that only applies further downstream, to a final `cdylib`
entry point this repo does not build - so this crate's own artifact is the `.rlib` itself). Two
independent, from-clean builds of that `.rlib` produce
byte-identical output. This is enforced on every push/PR by the `reproducible-build` job in
`.github/workflows/ci.yml`, and can be reproduced locally.

## How to verify
```
# Pinned nightly (see rust-toolchain.toml for why WASM needs a specific nightly rather than
# the crate's regular stable pin) + the wasm32 target:
rustup toolchain install nightly-2026-03-28 --profile minimal
rustup target add wasm32-unknown-unknown --toolchain nightly-2026-03-28

# Build 1, from clean:
rm -rf target/wasm32-unknown-unknown
cargo +nightly-2026-03-28 build --release --target wasm32-unknown-unknown
cp target/wasm32-unknown-unknown/release/libcrypto_core.rlib /tmp/build1.rlib

# Build 2, from clean:
rm -rf target/wasm32-unknown-unknown
cargo +nightly-2026-03-28 build --release --target wasm32-unknown-unknown

# Compare - both commands should agree the files are identical:
sha256sum /tmp/build1.rlib target/wasm32-unknown-unknown/release/libcrypto_core.rlib
cmp /tmp/build1.rlib target/wasm32-unknown-unknown/release/libcrypto_core.rlib
```

## Approach
- **Pinned toolchain** via `rust-toolchain.toml` (exact `rustc` channel + components) for the
  native build; a separately pinned nightly for the WASM target specifically (see above).
- **Locked dependencies** via `Cargo.lock`, checked in and used by both CI and local builds.
- **Verify by rebuild-and-diff:** build twice in a clean checkout; the artifacts must be
  byte-identical.

## What's not yet covered
This crate's own artifact (native `rlib` and WASM `rlib`) is verified. Reproducibility of any
final, end-user-facing binary that embeds this crate through a binding layer is a separate,
larger surface outside this crate's own scope.
