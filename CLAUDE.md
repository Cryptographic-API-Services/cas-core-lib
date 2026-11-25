# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

CAS Core Lib is a Rust crate that exposes a C-compatible FFI layer over [`cas-lib`](https://crates.io/crates/cas-lib), the crate that holds the actual cryptographic implementations. This crate itself contains almost no cryptography logic — it is the marshalling boundary that lets higher-level SDKs (.NET, Node.js/TypeScript) call into Rust crypto across the FFI.

The crate compiles to a C dynamic library (`crate-type = ["cdylib", "rlib"]`), producing `cas_core_lib.dll` (Windows) / `libcas_core_lib.so` (Linux) / `libcas_core_lib.dylib` (macOS) that consumers load and bind to. The `cdylib` exports only the `#[no_mangle]` C functions. The `rlib` is there so `cargo test` can link the crate. Released builds are attached to GitHub Releases (see Releases).

## Commands

```bash
cargo build --release --locked    # release build (what consumers ship) -> target/release/
cargo test --release --locked     # run all tests (each FFI module has inline #[test] fns)
cargo test --release --locked <name>  # run a single test by name, e.g. get_key_pair_test
cargo build                       # debug build -> target/debug/ (local iteration only)
```

The toolchain is pinned in `rust-toolchain.toml` (rustup installs it on first use), and `Cargo.lock` is committed. `--locked` makes Cargo fail instead of silently re-resolving when `Cargo.toml` and `Cargo.lock` disagree.

CI (`.github/workflows/*-test-pr.yml`) runs on every PR, whatever the base branch, on `ubuntu-latest`, `windows-latest` and `macos-latest`: `rustup toolchain install` (reads `rust-toolchain.toml`), then `cargo build --release --locked --verbose` and `cargo test --release --locked --verbose`. There is no linter or formatter step configured — match existing style.

## Architecture & FFI conventions

Every public function follows one rigid pattern. When adding or editing a function, replicate it exactly — the C# / TS callers depend on these invariants:

- **`#[no_mangle] pub extern "C"`** on every exported function so the symbol is callable across the FFI.
- **Pointer + length pairs.** Byte buffers cross the boundary as a raw pointer plus a separate `usize` length argument (e.g. `key: *const c_uchar, key_length: usize`). There are no Rust slices or `Vec`s in signatures.
- **Returning data via `#[repr(C)]` structs.** Functions that return buffers return a small `#[repr(C)]` struct (defined in the module's `types.rs`) holding a `*mut c_uchar` and a `usize length`. Strings (e.g. PEM keys) are returned as `*mut c_char` via `CString::into_raw`.
- **Handing buffers to the caller.** Put `export_bytes(&vec)` (from [`src/helpers.rs`](src/helpers.rs)) in the result struct's pointer field and `vec.len()` in its length field, and let the `Vec` drop normally. `export_bytes` copies the bytes into a Rust-allocator buffer with a hidden length header. Never return `vec.as_mut_ptr()` + `std::mem::forget(vec)` or a `libc::malloc` pointer: `free_bytes` cannot free those.
- **Freeing.** [`src/helpers.rs`](src/helpers.rs) exports `free_cstring` and `free_bytes` — the only functions consumers should call to release memory this crate handed out. Both release through the Rust global allocator, so `ZeroAlloc` wipes the memory. `free_bytes(ptr)` reads the length from the header `export_bytes` wrote.
- **Decoding inputs.** Incoming pointers are rebuilt with `std::slice::from_raw_parts(ptr, len).to_vec()` for bytes, or `CStr::from_ptr(...).to_str().unwrap().to_string()` for strings. Null checks are done with `assert!(!ptr.is_null())`.
- **Delegation.** The body should immediately delegate to a `cas-lib` trait implementation (e.g. `<CASAES256 as CASAES256Encryption>::encrypt_plaintext(...)`) and only handle marshalling around it. Keep crypto decisions in `cas-lib`, not here.

### Security-relevant global

[`src/lib.rs`](src/lib.rs) installs a custom `#[global_allocator]` (`zeroizing_alloc::ZeroAlloc`) that zeroes memory on deallocation. This is intentional for a crypto library — do not remove or replace it.

### Module layout

[`src/lib.rs`](src/lib.rs) is just the module tree. Each cryptographic primitive is its own module, and larger ones split FFI functions from their `#[repr(C)]` structs:

- Flat modules: `aes`, `ed25519`, `x25519`, `ascon_aead`, `zstd`, `helpers`
- `mod.rs` + `types.rs` pairs: `rsa`, `sha`, `hmac`, `hpke`, `blake2`
- Grouped: `password_hashers/` (argon2, scrypt, bcrypt) and `pqc/` (post-quantum, e.g. SLH-DSA)

Tests live inline in the same files as `#[test]` functions and typically exercise a full round-trip (e.g. generate key -> encrypt -> decrypt -> assert equality), calling the FFI functions directly.

## PR titles

PR titles must follow [Conventional Commits](https://www.conventionalcommits.org/) (`type(scope): summary`, `!` after the type for a breaking change), e.g. `fix(rsa): reject keys under 2048 bits`. PRs are squash-merged, so the title becomes the commit message and the `CHANGELOG.md` line. [`.github/workflows/pr-title.yml`](.github/workflows/pr-title.yml) checks it; allowed types: `feat`, `fix`, `security`, `changed`, `deprecated`, `docs`, `perf`, `refactor`, `test`, `ci`, `build`, `chore`, `revert`.

## C# bindings (csbindgen)

[`build.rs`](build.rs) runs csbindgen over every `.rs` file under `src/` and writes the .NET P/Invoke bindings to `$OUT_DIR/NativeMethods.g.cs` (under `target/<profile>/build/cas_core_lib-*/out/`). A plain build writes nothing outside `target/`.

To regenerate the bindings that cas-dotnet-sdk compiles, set `CAS_DOTNET_BINDINGS_DIR` to its `generated/` directory. A relative path is resolved against this crate's directory:

```bash
# from the cas-core-lib submodule inside cas-dotnet-sdk
CAS_DOTNET_BINDINGS_DIR=../cas-dotnet-sdk/generated cargo build --release
```

Changing the variable re-runs the build script. If you add or rename an FFI function, regenerate the bindings and commit `NativeMethods.g.cs` in cas-dotnet-sdk.

## Versioning

Versions are bumped by the release PR (see Releases), not by hand: mark FFI-breaking changes with `!` in the PR title. Keep the pinned `cas-lib` dependency version in sync with the behavior the consumer SDKs expect.

- `cas-lib` is pinned exactly (`cas-lib = "=x.y.z"`), so a new cas-lib release never comes in unannounced.
- `Cargo.lock` is committed and every CI build uses `--locked`: a `Cargo.toml` change without the matching `Cargo.lock` change fails CI. Commit both together.
- The Rust toolchain is pinned in `rust-toolchain.toml` (same version as cas-lib). Bump it in its own PR.
- Dependency and toolchain bumps go through PRs (Dependabot, #112), each one a reviewable `Cargo.lock` diff. Don't run a blanket `cargo update` as part of unrelated work.

## Releases

The crate isn't published to crates.io; a release is a `v<version>` tag plus a GitHub Release carrying the native libraries. Releases are made with [release-please](https://github.com/googleapis/release-please) (`release-type: rust`, configured in `release-please-config.json` like cas-typescript-sdk's), and `CHANGELOG.md` uses cas-lib's format. `.github/workflows/release.yml` runs on every push to `main`:

1. The `release-please` job opens or updates a `chore: release <version>` PR that bumps `Cargo.toml` (and `Cargo.lock`) and `.release-please-manifest.json`, and adds a `CHANGELOG.md` entry built from the Conventional Commit titles since the last release. Edit that PR to polish the entry; don't edit `CHANGELOG.md` entries anywhere else, and never bump `Cargo.toml`'s version by hand.
2. Merging it makes the job push the `v<version>` tag and create a GitHub Release whose body is that entry (job outputs `release_created` / `tag_name`).
3. Only then does the `build` matrix run, with a read-only token, on `ubuntu-latest` (x86_64 Linux), `windows-latest` (x86_64 Windows) and `macos-latest` (arm64 macOS). Each job checks out the tag, installs the toolchain from `rust-toolchain.toml`, fails if the tag isn't `v<Cargo.toml version>`, runs `cargo test --release --locked` and then `cargo build --release --locked`, and uploads the library plus the `NativeMethods.g.cs` that `build.rs` generated (the build sets `CAS_DOTNET_BINDINGS_DIR=bindings`).
4. The `upload` job runs in the `release` environment with `contents: write` only. It checks that the three `NativeMethods.g.cs` copies are identical (ignoring CRLF), writes `SHA256SUMS`, and attaches `libcas_core_lib.so`, `cas_core_lib.dll`, `libcas_core_lib.dylib`, `NativeMethods.g.cs` and `SHA256SUMS` with `gh release upload`. It never overwrites assets: if it fails halfway, delete the partial assets from the release by hand and rerun the job.

The assets keep the file names cargo produces, which are the names .NET resolves for `[DllImport("cas_core_lib")]`, so cas-dotnet-sdk can vendor them unchanged.  When adding a target, add it to the `build` matrix and to the `cp` list in `upload` together; two targets for one OS (e.g. Linux arm64) would need distinct asset names.

`changelog-sections` maps commit types to cas-lib's groups: `feat` → Added, `changed` → Changed, `deprecated` → Deprecated, `fix` → Fixed, `security` → Security, `docs` → Documentation, everything else → Other; `!` commits are also listed under Breaking changes. release-please has no catch-all, so a commit type it doesn't list is left out of the changelog. `bootstrap-sha` is the `main` commit before the first release-please release, and the manifest starts at `0.3.0` (never tagged); add `release-as` to the package in `release-please-config.json` to pin a specific version, and remove it after that release.

The PR that brings an epic branch into `main` must be merged with a **merge commit**, so each sub-PR's squashed Conventional Commit reaches `main` and gets its own changelog line. If it is squashed, put a release-please commit-override block listing every sub-PR title in the squash body; its start marker is `BEGIN_` immediately followed by `COMMIT_OVERRIDE`, and its end marker is the same with `END_`. Never write the literal marker in any other PR body, since release-please would rewrite that PR's changelog line.

Manual setup (repo admin):

- Create the `release` environment in Settings → Environments, ideally with required reviewers. GitHub creates a missing environment on first use, but with no protection rules.
- Optionally add the `RELEASE_PLEASE_TOKEN` secret (GitHub App or fine-grained PAT with Contents and Pull requests read/write). A release PR opened with the default `GITHUB_TOKEN` doesn't trigger the PR workflows.
