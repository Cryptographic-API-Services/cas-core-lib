use std::ffi::{c_char, c_uchar, CString};
use cas_lib::password_hashers::scrypt::CASScrypt;
use crate::helpers::{cas_error_code, string_from_c_str, string_result, utf8_from_ffi, verify_result, CasStringResult, CasVerifyResult};

// Passwords cross the ABI as a pointer + length (`*_bytes` functions), so they
// may contain NUL bytes. cas-lib takes them as `String`: bytes that are not
// valid UTF-8 return `InvalidInput` (4). None of these functions panic: a null
// pointer with a non-zero length returns `InvalidInput`.

/// Hashes a password with scrypt. `cpu_memory_cost` is log₂N (10–20),
/// `block_size` (`r`) 1–32 and `parallelism` (`p`) 1–16; scrypt also needs
/// log₂N < 16·r. Out-of-range values return `InvalidParameters` (6). The
/// password is `password_length` bytes of UTF-8 and may contain NUL bytes.
#[no_mangle]
pub extern "C" fn scrypt_hash_with_parameters_bytes(
    password: *const c_uchar,
    password_length: usize,
    cpu_memory_cost: u8,
    block_size: u32,
    parallelism: u32,
) -> CasStringResult {
    string_result(utf8_from_ffi(password, password_length).and_then(|password| {
        CASScrypt::hash_password_customized(password, cpu_memory_cost, block_size, parallelism)
    }))
}

/// Hashes a password with scrypt's default parameters. The password is
/// `password_length` bytes of UTF-8 and may contain NUL bytes.
#[no_mangle]
pub extern "C" fn scrypt_hash_bytes(password: *const c_uchar, password_length: usize) -> CasStringResult {
    string_result(utf8_from_ffi(password, password_length).and_then(CASScrypt::hash_password))
}

/// Verifies a password against a scrypt hash (a NUL-terminated string). The
/// password is `password_length` bytes of UTF-8.
#[no_mangle]
pub extern "C" fn scrypt_verify_bytes(
    hash_to_check: *const c_char,
    password: *const c_uchar,
    password_length: usize,
) -> CasVerifyResult {
    verify_result(
        string_from_c_str(hash_to_check)
            .and_then(|hash| Ok((hash, utf8_from_ffi(password, password_length)?)))
            .and_then(|(hash, password)| CASScrypt::verify_password(hash, password)),
    )
}

/// Deprecated: the password is a C string, so it ends at the first NUL byte.
/// Use `scrypt_hash_with_parameters_bytes`. A null pointer or invalid UTF-8
/// returns `InvalidInput` (4); out-of-range parameters return `InvalidParameters` (6).
#[deprecated(note = "the password is cut at the first NUL byte; use scrypt_hash_with_parameters_bytes")]
#[no_mangle]
pub extern "C" fn scrypt_hash_with_parameters(
    pass_to_hash: *const c_char,
    cpu_memory_cost: u8,
    block_size: u32,
    parallelism: u32,
) -> CasStringResult {
    string_result(string_from_c_str(pass_to_hash).and_then(|password| {
        CASScrypt::hash_password_customized(password, cpu_memory_cost, block_size, parallelism)
    }))
}

/// Deprecated: the password is a C string, so it ends at the first NUL byte.
/// Use `scrypt_hash_bytes`. A null pointer or invalid UTF-8 returns `InvalidInput` (4).
#[deprecated(note = "the password is cut at the first NUL byte; use scrypt_hash_bytes")]
#[no_mangle]
pub extern "C" fn scrypt_hash(pass_to_hash: *const c_char) -> CasStringResult {
    string_result(string_from_c_str(pass_to_hash).and_then(CASScrypt::hash_password))
}

#[test]
#[allow(deprecated)]
fn scrypt_hash_test() {
    let password = "PasswordToTest";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed = scrypt_hash(password_ptr);
    let hashed_ctr = unsafe { CString::from_raw(hashed.value) };
    let hashed_str = hashed_ctr.to_str().unwrap();
    assert_ne!(hashed_str, password);
}

/// Deprecated: the password is a C string, so it ends at the first NUL byte.
/// Use `scrypt_verify_bytes`. A null pointer or invalid UTF-8 returns `InvalidInput` (4).
#[deprecated(note = "the password is cut at the first NUL byte; use scrypt_verify_bytes")]
#[no_mangle]
pub extern "C" fn scrypt_verify(
    hash_to_check: *const c_char,
    pass_to_check: *const c_char,
) -> CasVerifyResult {
    verify_result(
        string_from_c_str(hash_to_check)
            .and_then(|hash| Ok((hash, string_from_c_str(pass_to_check)?)))
            .and_then(|(hash, password)| CASScrypt::verify_password(hash, password)),
    )
}

#[test]
#[allow(deprecated)]
fn scrypt_verify_test() {
    let password = "NotThePasswordYouAreLookingFor";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hash = scrypt_hash(password_ptr);
    let hash_ctr = unsafe { CString::from_raw(hash.value) };
    let hashed_bytes = hash_ctr.as_bytes_with_nul();
    let hashed_ptr = hashed_bytes.as_ptr() as *const i8;
    let is_valid = scrypt_verify(hashed_ptr, password_ptr);
    assert_eq!(true, is_valid.is_valid);
}

#[test]
#[allow(deprecated)]
fn scrypt_hash_with_parameters_bounds_test() {
    let invalid_parameters = cas_error_code(&cas_lib::error::CasError::InvalidParameters);
    let password = CString::new("DoNotUseThisPassword").unwrap();
    for (log_n, r, p) in [(9, 8, 1), (21, 8, 1), (63, 8, 1), (10, 0, 1), (10, 33, 1), (10, 8, 0), (10, 8, 17)] {
        let hash = scrypt_hash_with_parameters(password.as_ptr(), log_n, r, p);
        assert!(hash.value.is_null());
        assert_eq!(invalid_parameters, hash.error_code);
    }
    let hash = scrypt_hash_with_parameters(password.as_ptr(), 10, 8, 1);
    assert_eq!(0, hash.error_code);
    let is_valid = scrypt_verify(hash.value, password.as_ptr());
    assert_eq!(0, is_valid.error_code);
    assert!(is_valid.is_valid);
    unsafe { drop(CString::from_raw(hash.value)) };
}

#[test]
#[allow(deprecated)]
fn scrypt_verify_refuses_hostile_stored_hash_test() {
    let invalid_parameters = cas_error_code(&cas_lib::error::CasError::InvalidParameters);
    let password = CString::new("DoNotUseThisPassword").unwrap();
    let hash = scrypt_hash_with_parameters(password.as_ptr(), 10, 8, 1);
    let hash_string = unsafe { CString::from_raw(hash.value) }.into_string().unwrap();
    assert!(hash_string.contains("ln=10,r=8,p=1"));
    for hostile_params in ["ln=21,r=8,p=1", "ln=10,r=33,p=1", "ln=10,r=8,p=17"] {
        let hostile = CString::new(hash_string.replace("ln=10,r=8,p=1", hostile_params)).unwrap();
        let is_valid = scrypt_verify(hostile.as_ptr(), password.as_ptr());
        assert!(!is_valid.is_valid);
        assert_eq!(invalid_parameters, is_valid.error_code);
    }
}

#[cfg(test)]
fn scrypt_hash_bytes_value(bytes: &[u8]) -> CString {
    let hash = scrypt_hash_with_parameters_bytes(bytes.as_ptr(), bytes.len(), 10, 8, 1);
    assert_eq!(0, hash.error_code);
    unsafe { CString::from_raw(hash.value) }
}

#[test]
fn scrypt_bytes_round_trip_test() {
    let password = b"NotThePasswordYouAreLookingFor";
    let hash = scrypt_hash_bytes(password.as_ptr(), password.len());
    assert_eq!(0, hash.error_code);
    let is_valid = scrypt_verify_bytes(hash.value, password.as_ptr(), password.len());
    assert_eq!(0, is_valid.error_code);
    assert!(is_valid.is_valid);
    let is_valid = scrypt_verify_bytes(hash.value, password.as_ptr(), password.len() - 1);
    assert_eq!(0, is_valid.error_code);
    assert!(!is_valid.is_valid);
    crate::helpers::free_cstring(hash.value);
}

#[test]
#[allow(deprecated)]
fn scrypt_bytes_keeps_embedded_nul_test() {
    let password = b"abc\0def";
    let hash = scrypt_hash_bytes_value(password);
    let is_valid = scrypt_verify_bytes(hash.as_ptr(), password.as_ptr(), password.len());
    assert!(is_valid.is_valid);
    let is_valid = scrypt_verify_bytes(hash.as_ptr(), password.as_ptr(), 3);
    assert_eq!(0, is_valid.error_code);
    assert!(!is_valid.is_valid);
    let prefix = CString::new("abc").unwrap();
    let is_valid = scrypt_verify(hash.as_ptr(), prefix.as_ptr());
    assert_eq!(0, is_valid.error_code);
    assert!(!is_valid.is_valid);
}

#[test]
#[allow(deprecated)]
fn scrypt_rejects_invalid_utf8_and_null_test() {
    let invalid_input = cas_error_code(&cas_lib::error::CasError::InvalidInput);
    let invalid_utf8 = [b'a', 0xff, 0xfe, b'b'];
    let invalid_utf8_cstr = CString::new(invalid_utf8.to_vec()).unwrap();
    let hash = scrypt_hash_bytes_value(b"DoNotUseThisPassword");

    for result in [
        scrypt_hash_bytes(invalid_utf8.as_ptr(), invalid_utf8.len()),
        scrypt_hash_with_parameters_bytes(invalid_utf8.as_ptr(), invalid_utf8.len(), 10, 8, 1),
        scrypt_hash_bytes(std::ptr::null(), 8),
        scrypt_hash(invalid_utf8_cstr.as_ptr()),
        scrypt_hash(std::ptr::null()),
        scrypt_hash_with_parameters(invalid_utf8_cstr.as_ptr(), 10, 8, 1),
        scrypt_hash_with_parameters(std::ptr::null(), 10, 8, 1),
    ] {
        assert!(result.value.is_null());
        assert_eq!(invalid_input, result.error_code);
    }
    for result in [
        scrypt_verify_bytes(hash.as_ptr(), invalid_utf8.as_ptr(), invalid_utf8.len()),
        scrypt_verify_bytes(hash.as_ptr(), std::ptr::null(), 8),
        scrypt_verify_bytes(std::ptr::null(), b"x".as_ptr(), 1),
        scrypt_verify_bytes(invalid_utf8_cstr.as_ptr(), b"x".as_ptr(), 1),
        scrypt_verify(hash.as_ptr(), invalid_utf8_cstr.as_ptr()),
        scrypt_verify(hash.as_ptr(), std::ptr::null()),
        scrypt_verify(std::ptr::null(), hash.as_ptr()),
    ] {
        assert!(!result.is_valid);
        assert_eq!(invalid_input, result.error_code);
    }
}
