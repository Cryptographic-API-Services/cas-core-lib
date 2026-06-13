# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

CAS Core Lib is a Rust crate that exposes a C-compatible FFI layer over [`cas-lib`](https://crates.io/crates/cas-lib), the crate that holds the actual cryptographic implementations. This crate itself contains almost no cryptography logic — it is the marshalling boundary that lets higher-level SDKs (.NET, Node.js/TypeScript) call into Rust crypto across the FFI.

The crate compiles to a dynamic library (`crate-type = ["dylib"]`), producing `cas_core_lib.dll` (Windows) / `libcas_core_lib.so` (Linux) that consumers load and bind to.

## Commands

```bash
cargo build              # debug build -> target/debug/
cargo build --release    # release build (what consumers ship)
cargo test               # run all tests (each FFI module has inline #[test] fns)
cargo test <name>        # run a single test by name, e.g. cargo test get_key_pair_test
```

CI (`.github/workflows/`) runs `cargo build --verbose` and `cargo test --verbose` on both `ubuntu-latest` and `windows-latest` for every PR against `main`. There is no linter or formatter step configured — match existing style.

## Architecture & FFI conventions

Every public function follows one rigid pattern. When adding or editing a function, replicate it exactly — the C# / TS callers depend on these invariants:

- **`#[no_mangle] pub extern "C"`** on every exported function so the symbol is callable across the FFI.
- **Pointer + length pairs.** Byte buffers cross the boundary as a raw pointer plus a separate `usize` length argument (e.g. `key: *const c_uchar, key_length: usize`). There are no Rust slices or `Vec`s in signatures.
- **Returning data via `#[repr(C)]` structs.** Functions that return buffers return a small `#[repr(C)]` struct (defined in the module's `types.rs`) holding a `*mut c_uchar` and a `usize length`. Strings (e.g. PEM keys) are returned as `*mut c_char` via `CString::into_raw`.
- **Leaking memory deliberately.** To hand a buffer to the caller, the idiom is: build the `Vec`, call `reserve_exact` to make capacity == length, take `as_mut_ptr()`, then `std::mem::forget(vec)` so Rust does not free it. The caller is then responsible for freeing it.
- **Freeing.** [`src/helpers.rs`](src/helpers.rs) exports `free_cstring` and `free_bytes` — the only functions consumers should call to release memory this crate handed out. `free_bytes` uses `libc::free`.
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

## Versioning

When changing the public FFI surface, bump `version` in `Cargo.toml` and keep the pinned `cas-lib` dependency version in sync with the behavior the consumer SDKs expect.
