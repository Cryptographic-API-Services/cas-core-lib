use crate::helpers::{cas_error_code, string_from_c_str, string_result, utf8_from_ffi, verify_result, CasStringResult, CasVerifyResult};
use cas_lib::password_hashers::bcrypt::CASBCrypt;
use std::ffi::{c_char, c_uchar, CString};

// Passwords cross the ABI as a pointer + length (`*_bytes` functions), so they
// may contain NUL bytes. cas-lib takes them as `String`: bytes that are not
// valid UTF-8 return `InvalidInput` (4). Passwords over 72 bytes return
// `InvalidParameters` (6); bcrypt never truncates them. None of these
// functions panic: a null pointer with a non-zero length returns `InvalidInput`.

/// Hashes a password with bcrypt. `cost` must be 10–16; out-of-range values
/// return `InvalidParameters` (6). The password is `password_length` bytes of
/// UTF-8 (at most 72) and may contain NUL bytes. The bytes are `password_bytes`.
#[no_mangle]
pub extern "C" fn bcrypt_hash_with_parameters_bytes(password_bytes: *const c_uchar, password_length: usize, cost: u32) -> CasStringResult {
    string_result(utf8_from_ffi(password_bytes, password_length).and_then(|password| CASBCrypt::hash_password_customized(password, cost)))
}

/// Hashes a password with bcrypt at the default cost (12). The password is
/// `password_bytes` (`password_length` bytes of UTF-8, at most 72) and may contain NUL bytes.
#[no_mangle]
pub extern "C" fn bcrypt_hash_bytes(password_bytes: *const c_uchar, password_length: usize) -> CasStringResult {
    string_result(utf8_from_ffi(password_bytes, password_length).and_then(CASBCrypt::hash_password))
}

/// Verifies a password against a bcrypt hash (a NUL-terminated string). The
/// password is `password_bytes` (`password_length` bytes of UTF-8, at most 72).
#[no_mangle]
pub extern "C" fn bcrypt_verify_bytes(password_bytes: *const c_uchar, password_length: usize, hash: *const c_char) -> CasVerifyResult {
    verify_result(utf8_from_ffi(password_bytes, password_length).and_then(|password| Ok((password, string_from_c_str(hash)?))).and_then(|(password, hash)| CASBCrypt::verify_password(hash, password)))
}

/// Deprecated: the password is a C string, so it ends at the first NUL byte.
/// Use `bcrypt_hash_with_parameters_bytes`. A null pointer or invalid UTF-8
/// returns `InvalidInput` (4); out-of-range `cost` returns `InvalidParameters` (6).
#[deprecated(note = "the password is cut at the first NUL byte; use bcrypt_hash_with_parameters_bytes")]
#[no_mangle]
pub extern "C" fn bcrypt_hash_with_parameters(pass_to_hash: *const c_char, cost: u32) -> CasStringResult {
    string_result(string_from_c_str(pass_to_hash).and_then(|password| CASBCrypt::hash_password_customized(password, cost)))
}

/// Deprecated: the password is a C string, so it ends at the first NUL byte.
/// Use `bcrypt_hash_bytes`. A null pointer or invalid UTF-8 returns `InvalidInput` (4).
#[deprecated(note = "the password is cut at the first NUL byte; use bcrypt_hash_bytes")]
#[no_mangle]
pub extern "C" fn bcrypt_hash(pass_to_hash: *const c_char) -> CasStringResult {
    string_result(string_from_c_str(pass_to_hash).and_then(CASBCrypt::hash_password))
}

/// Deprecated: the password is a C string, so it ends at the first NUL byte.
/// Use `bcrypt_verify_bytes`. A null pointer or invalid UTF-8 returns `InvalidInput` (4).
#[deprecated(note = "the password is cut at the first NUL byte; use bcrypt_verify_bytes")]
#[no_mangle]
pub extern "C" fn bcrypt_verify(pass: *const c_char, hash: *const c_char) -> CasVerifyResult {
    verify_result(string_from_c_str(pass).and_then(|password| Ok((password, string_from_c_str(hash)?))).and_then(|(password, hash)| CASBCrypt::verify_password(hash, password)))
}

#[test]
#[allow(deprecated)]
fn bcrypt_hash_test() {
    let password = "PasswordToHash";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let passsword_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password = bcrypt_hash(passsword_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password.value) };
    let hashed_password_str = hashed_password_ctr.to_str().unwrap();
    assert_ne!(hashed_password_str, password);
}

#[test]
#[allow(deprecated)]
fn bcrypt_verify_test() {
    let password = "PasswordToHash";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password = bcrypt_hash(password_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password.value) };
    let hashed_password_bytes = hashed_password_ctr.as_bytes_with_nul();
    let hashed_password_ptr = hashed_password_bytes.as_ptr() as *const i8;
    let is_valid = bcrypt_verify(password_ptr, hashed_password_ptr);
    assert_eq!(true, is_valid.is_valid);
}

#[test]
#[allow(deprecated)]
fn bcrypt_72_byte_password_hashes_and_verifies_test() {
    // 24 three-byte characters: exactly 72 bytes of UTF-8, the bcrypt maximum.
    let password_cstr = CString::new("€".repeat(24)).unwrap();
    assert_eq!(72, password_cstr.as_bytes().len());
    let hashed_password = bcrypt_hash(password_cstr.as_ptr());
    assert_eq!(0, hashed_password.error_code);
    let is_valid = bcrypt_verify(password_cstr.as_ptr(), hashed_password.value);
    assert_eq!(0, is_valid.error_code);
    assert!(is_valid.is_valid);
    unsafe { drop(CString::from_raw(hashed_password.value)) };
}

#[test]
#[allow(deprecated)]
fn bcrypt_rejects_password_over_72_bytes_test() {
    let invalid_parameters = cas_error_code(&cas_lib::error::CasError::InvalidParameters);
    let short_cstr = CString::new("a".repeat(72)).unwrap();
    let long_cstr = CString::new("a".repeat(73)).unwrap();

    let hashed_password = bcrypt_hash(long_cstr.as_ptr());
    assert!(hashed_password.value.is_null());
    assert_eq!(invalid_parameters, hashed_password.error_code);

    let hashed_password = bcrypt_hash_with_parameters(long_cstr.as_ptr(), 10);
    assert!(hashed_password.value.is_null());
    assert_eq!(invalid_parameters, hashed_password.error_code);

    // A 73-byte password must not verify against the hash of its first 72 bytes.
    let short_hash = bcrypt_hash_with_parameters(short_cstr.as_ptr(), 10);
    assert_eq!(0, short_hash.error_code);
    let is_valid = bcrypt_verify(long_cstr.as_ptr(), short_hash.value);
    assert!(!is_valid.is_valid);
    assert_eq!(invalid_parameters, is_valid.error_code);
    unsafe { drop(CString::from_raw(short_hash.value)) };
}

#[test]
#[allow(deprecated)]
fn bcrypt_hash_with_parameters_bounds_test() {
    let invalid_parameters = cas_error_code(&cas_lib::error::CasError::InvalidParameters);
    let password = CString::new("DoNotUseThisPassword").unwrap();
    for cost in [0, 4, 9, 17, 31, u32::MAX] {
        let hash = bcrypt_hash_with_parameters(password.as_ptr(), cost);
        assert!(hash.value.is_null());
        assert_eq!(invalid_parameters, hash.error_code);
    }
    let hash = bcrypt_hash_with_parameters(password.as_ptr(), 10);
    assert_eq!(0, hash.error_code);
    let hash_string = unsafe { CString::from_raw(hash.value) }.into_string().unwrap();
    assert!(hash_string.starts_with("$2b$10$"));

    // A stored hash above the maximum cost is refused before any work is done.
    for hostile_cost in ["$2b$17$", "$2b$31$"] {
        let hostile = CString::new(hash_string.replacen("$2b$10$", hostile_cost, 1)).unwrap();
        let is_valid = bcrypt_verify(password.as_ptr(), hostile.as_ptr());
        assert!(!is_valid.is_valid);
        assert_eq!(invalid_parameters, is_valid.error_code);
    }
}

#[test]
#[allow(deprecated)]
fn bcrypt_verify_accepts_hash_below_minimum_cost_test() {
    // Older hashes below today's minimum cost still verify (bcrypt crate test vector, cost 4).
    let password = CString::new("correctbatteryhorsestapler").unwrap();
    let hash = CString::new("$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie").unwrap();
    let is_valid = bcrypt_verify(password.as_ptr(), hash.as_ptr());
    assert_eq!(0, is_valid.error_code);
    assert!(is_valid.is_valid);
}

#[cfg(test)]
fn bcrypt_hash_bytes_value(bytes: &[u8]) -> CString {
    let hash = bcrypt_hash_with_parameters_bytes(bytes.as_ptr(), bytes.len(), 10);
    assert_eq!(0, hash.error_code);
    unsafe { CString::from_raw(hash.value) }
}

#[test]
fn bcrypt_bytes_round_trip_test() {
    let password = b"PasswordToHash";
    let hash = bcrypt_hash_bytes(password.as_ptr(), password.len());
    assert_eq!(0, hash.error_code);
    let is_valid = bcrypt_verify_bytes(password.as_ptr(), password.len(), hash.value);
    assert_eq!(0, is_valid.error_code);
    assert!(is_valid.is_valid);
    let wrong = b"PasswordToHasH";
    let is_valid = bcrypt_verify_bytes(wrong.as_ptr(), wrong.len(), hash.value);
    assert_eq!(0, is_valid.error_code);
    assert!(!is_valid.is_valid);
    crate::helpers::free_cstring(hash.value);
}

#[test]
#[allow(deprecated)]
fn bcrypt_bytes_keeps_embedded_nul_test() {
    let password = b"abc\0def";
    let hash = bcrypt_hash_bytes_value(password);
    let is_valid = bcrypt_verify_bytes(password.as_ptr(), password.len(), hash.as_ptr());
    assert!(is_valid.is_valid);
    // The bytes after the NUL count: the prefix alone does not verify, by either API.
    let is_valid = bcrypt_verify_bytes(password.as_ptr(), 3, hash.as_ptr());
    assert_eq!(0, is_valid.error_code);
    assert!(!is_valid.is_valid);
    let prefix = CString::new("abc").unwrap();
    let is_valid = bcrypt_verify(prefix.as_ptr(), hash.as_ptr());
    assert_eq!(0, is_valid.error_code);
    assert!(!is_valid.is_valid);
}

#[test]
fn bcrypt_bytes_72_vs_73_byte_password_test() {
    let invalid_parameters = cas_error_code(&cas_lib::error::CasError::InvalidParameters);
    let long = [b'a'; 73];
    let short_hash = bcrypt_hash_bytes_value(&long[..72]);
    let is_valid = bcrypt_verify_bytes(long.as_ptr(), 72, short_hash.as_ptr());
    assert_eq!(0, is_valid.error_code);
    assert!(is_valid.is_valid);

    let hash = bcrypt_hash_bytes(long.as_ptr(), long.len());
    assert!(hash.value.is_null());
    assert_eq!(invalid_parameters, hash.error_code);
    let hash = bcrypt_hash_with_parameters_bytes(long.as_ptr(), long.len(), 10);
    assert!(hash.value.is_null());
    assert_eq!(invalid_parameters, hash.error_code);
    // A 73-byte password must not verify against the hash of its first 72 bytes.
    let is_valid = bcrypt_verify_bytes(long.as_ptr(), long.len(), short_hash.as_ptr());
    assert!(!is_valid.is_valid);
    assert_eq!(invalid_parameters, is_valid.error_code);
}

#[test]
#[allow(deprecated)]
fn bcrypt_rejects_invalid_utf8_and_null_test() {
    let invalid_input = cas_error_code(&cas_lib::error::CasError::InvalidInput);
    let invalid_utf8 = [b'a', 0xff, 0xfe, b'b'];
    let invalid_utf8_cstr = CString::new(invalid_utf8.to_vec()).unwrap();
    let hash = bcrypt_hash_bytes_value(b"DoNotUseThisPassword");

    for result in [bcrypt_hash_bytes(invalid_utf8.as_ptr(), invalid_utf8.len()), bcrypt_hash_with_parameters_bytes(invalid_utf8.as_ptr(), invalid_utf8.len(), 10), bcrypt_hash_bytes(std::ptr::null(), 8), bcrypt_hash(invalid_utf8_cstr.as_ptr()), bcrypt_hash(std::ptr::null()), bcrypt_hash_with_parameters(invalid_utf8_cstr.as_ptr(), 10), bcrypt_hash_with_parameters(std::ptr::null(), 10)] {
        assert!(result.value.is_null());
        assert_eq!(invalid_input, result.error_code);
    }
    for result in [
        bcrypt_verify_bytes(invalid_utf8.as_ptr(), invalid_utf8.len(), hash.as_ptr()),
        bcrypt_verify_bytes(std::ptr::null(), 8, hash.as_ptr()),
        bcrypt_verify_bytes(b"x".as_ptr(), 1, std::ptr::null()),
        bcrypt_verify_bytes(b"x".as_ptr(), 1, invalid_utf8_cstr.as_ptr()),
        bcrypt_verify(invalid_utf8_cstr.as_ptr(), hash.as_ptr()),
        bcrypt_verify(std::ptr::null(), hash.as_ptr()),
        bcrypt_verify(hash.as_ptr(), std::ptr::null()),
    ] {
        assert!(!result.is_valid);
        assert_eq!(invalid_input, result.error_code);
    }
}
