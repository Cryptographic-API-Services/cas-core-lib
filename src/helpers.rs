use std::alloc::{alloc, dealloc, handle_alloc_error, Layout};
use std::ffi::{c_char, c_uchar, CString};

use cas_lib::error::CasError;

/// Result of a verification (`verify`-style) FFI call.
///
/// cas-lib's verify operations now return `CasResult<bool>`, so a plain `bool`
/// can no longer distinguish "signature did not match" (`is_valid == false`,
/// `error_code == 0`) from "the inputs were malformed" (`is_valid == false`,
/// `error_code != 0`). This struct carries both across the boundary.
#[repr(C)]
pub struct CasVerifyResult {
    pub is_valid: bool,
    pub error_code: i32,
}

/// Result of an FFI call that hands back a C string (e.g. a password hash).
///
/// `value` is null when `error_code` is non-zero. The caller still frees a
/// non-null `value` with [`free_cstring`].
#[repr(C)]
pub struct CasStringResult {
    pub value: *mut c_char,
    pub error_code: i32,
}

/// Maps a [`CasError`] to the stable numeric code surfaced through the FFI in
/// the `error_code` field of every result struct. `0` always means success.
///
/// These values are part of the ABI contract with the consumer SDKs, so they
/// must stay stable even if cas-lib reorders the `CasError` enum — do not switch
/// this to an `as i32` cast on the enum.
pub fn cas_error_code(error: &CasError) -> i32 {
    match error {
        CasError::InvalidKey => 1,
        CasError::InvalidNonce => 2,
        CasError::InvalidSignature => 3,
        CasError::InvalidInput => 4,
        CasError::InvalidPemKey => 5,
        CasError::InvalidParameters => 6,
        CasError::EncryptionFailed => 7,
        CasError::DecryptionFailed => 8,
        CasError::SigningFailed => 9,
        CasError::KeyGenerationFailed => 10,
        CasError::PasswordHashingFailed => 11,
        CasError::CompressionFailed => 12,
    }
}

/// Size of the hidden header in front of every buffer from [`export_bytes`].
/// The header holds the buffer length so that [`free_bytes`] can rebuild the
/// allocation's `Layout` from the pointer alone.
const BYTES_HEADER: usize = std::mem::size_of::<usize>();

fn exported_bytes_layout(length: usize) -> Layout {
    let size = BYTES_HEADER
        .checked_add(length)
        .expect("exported buffer length overflows usize");
    Layout::from_size_align(size, std::mem::align_of::<usize>())
        .expect("exported buffer length overflows Layout")
}

/// Copies `bytes` into a buffer that the FFI caller owns and returns a pointer
/// to it. The caller releases it with [`free_bytes`].
///
/// The buffer is allocated through the Rust global allocator (`ZeroAlloc`), so
/// `free_bytes` wipes it on release. The source `Vec` is dropped normally, which
/// wipes that copy too. Do not hand out `Vec::as_mut_ptr` + `mem::forget`
/// pointers instead: `free_bytes` cannot free them.
pub(crate) fn export_bytes(bytes: &[u8]) -> *mut c_uchar {
    let layout = exported_bytes_layout(bytes.len());
    unsafe {
        let base = alloc(layout);
        if base.is_null() {
            handle_alloc_error(layout);
        }
        (base as *mut usize).write(bytes.len());
        let data = base.add(BYTES_HEADER);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), data, bytes.len());
        data
    }
}

/// Releases a string returned by this library (`CString::into_raw`). The
/// string goes back through `ZeroAlloc`, which wipes it. The caller must not
/// write an extra NUL into it, because the length is recovered with `strlen`.
#[no_mangle]
pub extern "C" fn free_cstring(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        drop(CString::from_raw(s));
    };
}

/// Releases a byte buffer returned by this library. `ptr` must be a buffer
/// pointer from one of the result structs (that is, from [`export_bytes`]) and
/// must not be freed twice. Null is ignored.
///
/// The buffer goes back through the Rust global allocator, so `ZeroAlloc` wipes
/// it (length header included) before the memory is reused.
#[no_mangle]
pub extern "C" fn free_bytes(ptr: *mut c_uchar) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let base = ptr.sub(BYTES_HEADER);
        let length = (base as *const usize).read();
        dealloc(base, exported_bytes_layout(length));
    }
}

#[test]
fn export_bytes_round_trip_test() {
    for length in [0usize, 1, 7, 8, 32, 4096, 1 << 20] {
        let source: Vec<u8> = (0..length).map(|i| i as u8).collect();
        let ptr = export_bytes(&source);
        assert!(!ptr.is_null());
        assert_eq!(ptr as usize % std::mem::align_of::<usize>(), 0);
        let exported = unsafe { std::slice::from_raw_parts(ptr, length) };
        assert_eq!(exported, source.as_slice());
        let header = unsafe { (ptr.sub(BYTES_HEADER) as *const usize).read() };
        assert_eq!(header, length);
        free_bytes(ptr);
    }
}

#[test]
fn free_bytes_null_is_noop_test() {
    free_bytes(std::ptr::null_mut());
}

#[test]
fn free_cstring_round_trip_test() {
    free_cstring(CString::new("not a secret").unwrap().into_raw());
    free_cstring(std::ptr::null_mut());
}

#[test]
fn free_bytes_releases_ffi_results_test() {
    let aes_key = crate::aes::aes_256_key();
    assert_eq!(aes_key.length, 32);
    free_bytes(aes_key.key);

    let x25519_keys = crate::x25519::generate_secret_and_public_key();
    free_bytes(x25519_keys.secret_key);
    free_bytes(x25519_keys.public_key);

    let ml_kem_keys = crate::pqc::ml_kem::ml_kem_1024_generate_key_pair();
    free_bytes(ml_kem_keys.secret_key_ptr as *mut c_uchar);
    free_bytes(ml_kem_keys.public_key_ptr as *mut c_uchar);

    let password = CString::new("DoNotUseThisPassword").unwrap();
    let hash = crate::password_hashers::argon2::argon2_hash_password_parameters(1024, 2, 1, password.as_ptr());
    assert_eq!(hash.error_code, 0);
    let kdf = crate::password_hashers::argon2::argon2_derive_aes_256_key(hash.value);
    assert_eq!(kdf.error_code, 0);
    assert_eq!(kdf.length, 32);
    free_bytes(kdf.key);
    free_cstring(hash.value);
}
