use std::ffi::{c_char, c_uchar, c_void, CString};

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

#[no_mangle]
pub extern "C" fn free_cstring(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        drop(CString::from_raw(s));
    };
}

#[no_mangle]
pub extern "C" fn free_bytes(ptr: *mut c_uchar) {
    unsafe {
        if ptr.is_null() {
            return;
        }
        libc::free(ptr as *mut c_void);
    }
}
