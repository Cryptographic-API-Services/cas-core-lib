use std::path::{Path, PathBuf};

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
fn main() {
    let mut inputs = Vec::new();
    collect_rs_files(Path::new("src"), &mut inputs);
    inputs.sort();

    for input in &inputs {
        println!("cargo:rerun-if-changed={}", input.display());
    }
    println!("cargo:rerun-if-changed=build.rs");

    // Emit into the C# SDK project so the binding is a tracked artifact of the
    // .NET repo (the project consumes it as source). Anchor on CARGO_MANIFEST_DIR
    // so the path is correct no matter what working directory cargo is invoked from.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let out_dir = Path::new(manifest_dir).join("../cas-dotnet-sdk/generated");
    std::fs::create_dir_all(&out_dir).expect("failed to create generated/ output directory");

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
        .generate_csharp_file(out_dir.join("NativeMethods.g.cs"))
        .expect("failed to generate C# bindings");
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
