use std::{
    ffi::{c_char, CStr, CString}
};
use cas_lib::password_hashers::{bcrypt::CASBCrypt};
use crate::helpers::{cas_error_code, CasStringResult, CasVerifyResult};

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

