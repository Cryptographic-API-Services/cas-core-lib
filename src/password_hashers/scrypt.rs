use std::ffi::{c_char, CStr, CString};
use cas_lib::password_hashers::{scrypt::CASScrypt};
use crate::helpers::{cas_error_code, CasStringResult, CasVerifyResult};

/// Hashes with scrypt. `cpu_memory_cost` is log₂N (10–20), `block_size` (`r`)
/// 1–32 and `parallelism` (`p`) 1–16; scrypt also needs log₂N < 16·r.
/// Out-of-range values return `InvalidParameters` (6).
#[no_mangle]
pub extern "C" fn scrypt_hash_with_parameters(
    pass_to_hash: *const c_char,
    cpu_memory_cost: u8,
    block_size: u32,
    parallelism: u32,
) -> CasStringResult {
    let string_pass = unsafe {
        assert!(!pass_to_hash.is_null());

        CStr::from_ptr(pass_to_hash)
    }
    .to_str()
    .unwrap()
    .to_string();
    match CASScrypt::hash_password_customized(string_pass, cpu_memory_cost, block_size, parallelism) {
        Ok(new_hash) => CasStringResult { value: CString::new(new_hash).unwrap().into_raw(), error_code: 0 },
        Err(e) => CasStringResult { value: std::ptr::null_mut(), error_code: cas_error_code(&e) },
    }
}

#[no_mangle]
pub extern "C" fn scrypt_hash(pass_to_hash: *const c_char) -> CasStringResult {
    let string_pass = unsafe {
        assert!(!pass_to_hash.is_null());

        CStr::from_ptr(pass_to_hash)
    }
    .to_str()
    .unwrap()
    .to_string();
    match CASScrypt::hash_password(string_pass) {
        Ok(new_hash) => CasStringResult { value: CString::new(new_hash).unwrap().into_raw(), error_code: 0 },
        Err(e) => CasStringResult { value: std::ptr::null_mut(), error_code: cas_error_code(&e) },
    }
}

#[test]
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

#[no_mangle]
pub extern "C" fn scrypt_verify(
    hash_to_check: *const c_char,
    pass_to_check: *const c_char,
) -> CasVerifyResult {
    let string_hash = unsafe {
        assert!(!hash_to_check.is_null());

        CStr::from_ptr(hash_to_check)
    }
    .to_str()
    .unwrap()
    .to_string();

    let string_pass = unsafe {
        assert!(!pass_to_check.is_null());

        CStr::from_ptr(pass_to_check)
    }
    .to_str()
    .unwrap()
    .to_string();

    match CASScrypt::verify_password(string_hash, string_pass) {
        Ok(is_valid) => CasVerifyResult { is_valid, error_code: 0 },
        Err(e) => CasVerifyResult { is_valid: false, error_code: cas_error_code(&e) },
    }
}

#[test]
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
