use std::path::Path;

/// Generates the C# P/Invoke bindings consumed by cas-dotnet-sdk straight from
/// this crate's `extern "C"` surface, using csbindgen (Cysharp).
///
/// This is the first iteration of the migration tracked in cas-dotnet-sdk#190 /
/// cas-core-lib#79: instead of hand-writing (and duplicating across Windows/Linux)
/// the `[DllImport]` declarations and `#[repr(C)]` struct mirrors on the .NET side,
/// we transcribe them automatically from the Rust source.
///
/// Pilot scope: the `Hashers` category only (SHA + Blake2) plus the shared
/// `free_*` helpers. The remaining categories still use the legacy hand-written
/// wrappers until they are migrated in later iterations.
fn main() {
    // Pilot inputs. As more categories migrate, add their `mod.rs` + `types.rs`
    // files here (or switch to a directory glob) and the bindings grow with them.
    let inputs = [
        "src/sha/mod.rs",
        "src/sha/types.rs",
        "src/blake2/mod.rs",
        "src/blake2/types.rs",
        "src/helpers.rs",
    ];

    for input in inputs {
        println!("cargo:rerun-if-changed={input}");
    }
    println!("cargo:rerun-if-changed=build.rs");

    // Emit into the C# SDK project so the binding is a tracked artifact of the
    // .NET repo (the project consumes it as source). Anchor on CARGO_MANIFEST_DIR
    // so the path is correct no matter what working directory cargo is invoked from.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let out_dir = Path::new(manifest_dir).join("../cas-dotnet-sdk/generated");
    std::fs::create_dir_all(&out_dir).expect("failed to create generated/ output directory");

    let mut builder = csbindgen::Builder::default();
    for input in inputs {
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
