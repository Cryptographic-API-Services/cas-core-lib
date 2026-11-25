use std::{
    ffi::{c_char, CStr, CString}
};
use cas_lib::password_hashers::{bcrypt::CASBCrypt};
use crate::helpers::{cas_error_code, CasStringResult, CasVerifyResult};

/// Hashes with bcrypt. `cost` must be 10–16; out-of-range values return
/// `InvalidParameters` (6).
#[no_mangle]
pub extern "C" fn bcrypt_hash_with_parameters(pass_to_hash: *const c_char, cost: u32) -> CasStringResult {
    let string_pass = unsafe {
        assert!(!pass_to_hash.is_null());

        CStr::from_ptr(pass_to_hash)
    }
    .to_str()
    .unwrap()
    .to_string();
    match CASBCrypt::hash_password_customized(string_pass, cost) {
        Ok(new_hashed) => CasStringResult { value: CString::new(new_hashed).unwrap().into_raw(), error_code: 0 },
        Err(e) => CasStringResult { value: std::ptr::null_mut(), error_code: cas_error_code(&e) },
    }
}


#[no_mangle]
pub extern "C" fn bcrypt_hash(pass_to_hash: *const c_char) -> CasStringResult {
    let string_pass = unsafe {
        assert!(!pass_to_hash.is_null());

        CStr::from_ptr(pass_to_hash)
    }
    .to_str()
    .unwrap()
    .to_string();
    match CASBCrypt::hash_password(string_pass) {
        Ok(new_hashed) => CasStringResult { value: CString::new(new_hashed).unwrap().into_raw(), error_code: 0 },
        Err(e) => CasStringResult { value: std::ptr::null_mut(), error_code: cas_error_code(&e) },
    }
}

#[test]
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

#[no_mangle]
pub extern "C" fn bcrypt_verify(pass: *const c_char, hash: *const c_char) -> CasVerifyResult {
    let string_pass = unsafe {
        assert!(!pass.is_null());

        CStr::from_ptr(pass)
    }
    .to_str()
    .unwrap()
    .to_string();

    let string_hash = unsafe {
        assert!(!hash.is_null());

        CStr::from_ptr(hash)
    }
    .to_str()
    .unwrap()
    .to_string();
    match CASBCrypt::verify_password(string_hash, string_pass) {
        Ok(is_valid) => CasVerifyResult { is_valid, error_code: 0 },
        Err(e) => CasVerifyResult { is_valid: false, error_code: cas_error_code(&e) },
    }
}

#[test]
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
fn bcrypt_verify_accepts_hash_below_minimum_cost_test() {
    // Older hashes below today's minimum cost still verify (bcrypt crate test vector, cost 4).
    let password = CString::new("correctbatteryhorsestapler").unwrap();
    let hash = CString::new("$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie").unwrap();
    let is_valid = bcrypt_verify(password.as_ptr(), hash.as_ptr());
    assert_eq!(0, is_valid.error_code);
    assert!(is_valid.is_valid);
}
