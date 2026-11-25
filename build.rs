use std::path::{Path, PathBuf};

/// Directory to copy the generated bindings into (e.g. cas-dotnet-sdk's
/// `generated/`). Unset by default, so a plain build writes only to OUT_DIR.
const BINDINGS_DIR_ENV: &str = "CAS_DOTNET_BINDINGS_DIR";
const BINDINGS_FILE: &str = "NativeMethods.g.cs";

/// Generates the C# P/Invoke bindings consumed by cas-dotnet-sdk straight from
/// this crate's `extern "C"` surface, using csbindgen (Cysharp).
///
/// Migration tracked in cas-dotnet-sdk#190 / cas-core-lib#79: instead of
/// hand-writing (and duplicating across Windows/Linux) the `[DllImport]`
/// declarations and `#[repr(C)]` struct mirrors on the .NET side, we transcribe
/// them automatically from the Rust source.
///
/// Every `.rs` file under `src/` is fed to csbindgen, so the full FFI surface is
/// covered and new modules are picked up automatically with no build.rs change.
///
/// The file is always written to `$OUT_DIR/NativeMethods.g.cs`. When
/// `CAS_DOTNET_BINDINGS_DIR` is set, it is also copied into that directory.
fn main() {
    let mut inputs = Vec::new();
    collect_rs_files(Path::new("src"), &mut inputs);
    inputs.sort();

    for input in &inputs {
        println!("cargo:rerun-if-changed={}", input.display());
    }
    println!("cargo:rerun-if-changed=build.rs");

    println!("cargo:rerun-if-env-changed={BINDINGS_DIR_ENV}");

    // Cargo build scripts may only write to OUT_DIR, so that is the default
    // target. cas-dotnet-sdk sets CAS_DOTNET_BINDINGS_DIR to its `generated/`
    // directory to get a copy there as well (see CLAUDE.md).
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let generated = out_dir.join(BINDINGS_FILE);

    let mut builder = csbindgen::Builder::default();
    for input in &inputs {
        builder = builder.input_extern_file(input);
    }

    builder
        // .NET maps a bare "cas_core_lib" to cas_core_lib.dll on Windows and
        // libcas_core_lib.so on Linux automatically, so one binding set serves
        // both platforms — this is what collapses the old Windows/ + Linux/ split.
        .csharp_dll_name("cas_core_lib")
        .csharp_namespace("CasCoreLib")
        .csharp_class_name("NativeMethods")
        .csharp_use_nint_types(true)
        .generate_csharp_file(&generated)
        .expect("failed to generate C# bindings");

    // Relative paths are resolved against this crate's directory, which is the
    // build script's working directory.
    if let Some(dir) = std::env::var_os(BINDINGS_DIR_ENV).filter(|d| !d.is_empty()) {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("{BINDINGS_DIR_ENV}: create {dir:?}: {e}"));
        std::fs::copy(&generated, dir.join(BINDINGS_FILE))
            .unwrap_or_else(|e| panic!("{BINDINGS_DIR_ENV}: copy bindings into {dir:?}: {e}"));
    }
}

/// Recursively collects every `.rs` file under `dir`.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}
