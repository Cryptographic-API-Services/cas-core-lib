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
        CasError::DecompressionLimitExceeded => 13,
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

/// Rebuilds an input buffer from a pointer + length pair without panicking.
///
/// FFI callers often marshal an empty array (empty AAD, empty plaintext) as a
/// null pointer, so a null pointer is accepted when `length == 0`. A null
/// pointer with a non-zero length is reported as `InvalidInput` through the
/// result's `error_code` rather than panicking across the ABI.
pub fn bytes_from_ffi(ptr: *const c_uchar, length: usize) -> Result<Vec<u8>, CasError> {
    // `from_raw_parts` is immediate undefined behavior when `length` exceeds
    // `isize::MAX`, and when `ptr` is null for any length including zero.
    if length > isize::MAX as usize || (ptr.is_null() && length != 0) {
        return Err(CasError::InvalidInput);
    }
    if length == 0 {
        return Ok(Vec::new());
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, length) }.to_vec())
}

/// Rebuilds a UTF-8 string (e.g. a password) from a pointer + length pair
/// without panicking. cas-lib's password hashers take `String`, so bytes that
/// are not valid UTF-8 return `InvalidInput`, as does a null pointer with a
/// non-zero length. Embedded NUL bytes are kept: they are valid UTF-8.
///
/// On failure the copied bytes are dropped through `ZeroAlloc`, which wipes them.
pub(crate) fn utf8_from_ffi(ptr: *const c_uchar, length: usize) -> Result<String, CasError> {
    String::from_utf8(bytes_from_ffi(ptr, length)?).map_err(|_| CasError::InvalidInput)
}

/// Reads a NUL-terminated UTF-8 C string without panicking. A null pointer or
/// bytes that are not valid UTF-8 return `InvalidInput`. The string ends at the
/// first NUL, so use a pointer + length variant for data that may contain one.
pub(crate) fn string_from_c_str(ptr: *const c_char) -> Result<String, CasError> {
    if ptr.is_null() {
        return Err(CasError::InvalidInput);
    }
    let bytes = unsafe { std::ffi::CStr::from_ptr(ptr) }.to_bytes().to_vec();
    String::from_utf8(bytes).map_err(|_| CasError::InvalidInput)
}

/// Turns a cas-lib string result into a [`CasStringResult`]. A string with an
/// interior NUL can't be returned as a C string and reports
/// `PasswordHashingFailed`; hashes never contain one.
pub(crate) fn string_result(result: Result<String, CasError>) -> CasStringResult {
    match result.and_then(|value| CString::new(value).map_err(|_| CasError::PasswordHashingFailed)) {
        Ok(value) => CasStringResult { value: value.into_raw(), error_code: 0 },
        Err(e) => CasStringResult { value: std::ptr::null_mut(), error_code: cas_error_code(&e) },
    }
}

/// Turns a cas-lib verify result into a [`CasVerifyResult`].
pub(crate) fn verify_result(result: Result<bool, CasError>) -> CasVerifyResult {
    match result {
        Ok(is_valid) => CasVerifyResult { is_valid, error_code: 0 },
        Err(e) => CasVerifyResult { is_valid: false, error_code: cas_error_code(&e) },
    }
}

// Copies a returned buffer. The original is leaked, like the other inline tests do.
#[cfg(test)]
pub fn take_bytes(ptr: *mut c_uchar, length: usize) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(ptr, length) }.to_vec()
}

/// Releases a string returned by this library (`CString::into_raw`). The
/// string goes back through `ZeroAlloc`, which wipes it. The caller must not
/// write an extra NUL into it, because the length is recovered with `strlen`.
///
/// Only for `*mut c_char` fields (`CasStringResult::value`, the PEM strings in
/// `RsaKeyPair`). Never pass a byte buffer: use [`free_bytes`] for those. Each
/// string must be freed exactly once. Null is ignored.
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

/// Frees one buffer field of a result struct with [`free_bytes`], then sets the
/// pointer to null and the length to 0. The `free_<struct>` functions use it, so
/// calling one of them twice on the same struct is harmless.
pub(crate) fn free_bytes_field(ptr: &mut *mut c_uchar, length: &mut usize) {
    free_bytes(*ptr);
    *ptr = std::ptr::null_mut();
    *length = 0;
}

/// Frees one string field of a result struct with [`free_cstring`], then sets
/// the pointer to null.
pub(crate) fn free_cstring_field(ptr: &mut *mut c_char) {
    free_cstring(*ptr);
    *ptr = std::ptr::null_mut();
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
fn bytes_from_ffi_rejects_null_and_oversized_length_test() {
    let invalid = cas_error_code(&CasError::InvalidInput);
    assert!(bytes_from_ffi(std::ptr::null(), 0).unwrap().is_empty());
    assert_eq!(invalid, cas_error_code(&bytes_from_ffi(std::ptr::null(), 4).unwrap_err()));
    let dummy = [1u8];
    assert_eq!(
        invalid,
        cas_error_code(&bytes_from_ffi(dummy.as_ptr(), (isize::MAX as usize).saturating_add(1)).unwrap_err())
    );
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
#[allow(deprecated)]
fn free_bytes_releases_ffi_results_test() {
    let aes_key = crate::aes::aes_256_key();
    assert_eq!(aes_key.length, 32);
    free_bytes(aes_key.key);

    let x25519_keys = crate::x25519::generate_secret_and_public_key();
    free_bytes(x25519_keys.secret_key);
    free_bytes(x25519_keys.public_key);

    let ml_kem_keys = crate::pqc::ml_kem::ml_kem_1024_generate_key_pair();
    free_bytes(ml_kem_keys.secret_key_ptr);
    free_bytes(ml_kem_keys.public_key_ptr);

    let password = CString::new("DoNotUseThisPassword").unwrap();
    let hash = crate::password_hashers::argon2::argon2_hash_password_parameters(19, 2, 1, password.as_ptr());
    assert_eq!(hash.error_code, 0);
    free_cstring(hash.value);

    let salt = crate::password_hashers::argon2::argon2_generate_salt();
    assert_eq!(salt.length, 16);
    let kdf = crate::password_hashers::argon2::argon2_derive_aes_256_key_with_salt(
        password.as_ptr() as *const c_uchar,
        password.as_bytes().len(),
        salt.salt,
        salt.length,
    );
    assert_eq!(kdf.error_code, 0);
    assert_eq!(kdf.length, 32);
    free_bytes(kdf.key);
    free_bytes(salt.salt);
}
