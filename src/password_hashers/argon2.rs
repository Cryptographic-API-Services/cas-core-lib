use std::ffi::{c_char, CStr, CString};
use cas_lib::password_hashers::argon2::CASArgon;

use super::types::Argon2KDFAes128;
use crate::helpers::{cas_error_code, CasStringResult, CasVerifyResult};


#[no_mangle]
pub extern "C" fn argon2_hash_password_parameters(memory_cost: u32, iterations: u32, parallelism: u32, password_to_hash: *const c_char) -> CasStringResult {
    let password = unsafe {
        assert!(!password_to_hash.is_null());
        CStr::from_ptr(password_to_hash)
    }
    .to_str()
    .unwrap()
    .to_string();

    match CASArgon::hash_password_parameters(memory_cost, iterations, parallelism, password) {
        Ok(hash) => CasStringResult { value: CString::new(hash).unwrap().into_raw(), error_code: 0 },
        Err(e) => CasStringResult { value: std::ptr::null_mut(), error_code: cas_error_code(&e) },
    }
}

#[test]
fn argon2_hash_password_parameters_test() {
    let password = "TestPassword123!";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();

    let hash = argon2_hash_password_parameters(1024, 2, 1, password_bytes.as_ptr() as *const i8);
    let hash_cstr = unsafe { CString::from_raw(hash.value) };
    let hash_str = hash_cstr.to_str().unwrap();
    assert!(!hash_str.is_empty());
    assert_ne!(hash_str, password);
}

#[no_mangle]
pub extern "C" fn argon2_derive_aes_128_key(hashed_password: *const c_char) -> Argon2KDFAes128 {
    let hashed_password_bytes = unsafe {
        assert!(!hashed_password.is_null());
        CStr::from_ptr(hashed_password)
    }.to_bytes().to_vec();
    match CASArgon::derive_aes_128_key(hashed_password_bytes) {
        Ok(key) => {
            let key_ptr = unsafe {
                let ptr = libc::malloc(key.len()) as *mut u8;
                std::ptr::copy_nonoverlapping(key.as_ptr(), ptr, key.len());
                ptr
            };
            Argon2KDFAes128 {
                key: key_ptr,
                length: key.len(),
                error_code: 0,
            }
        }
        Err(e) => Argon2KDFAes128 {
            key: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

#[no_mangle]
pub extern "C" fn argon2_derive_aes_256_key(hashed_password: *const c_char) -> Argon2KDFAes128 {
    let hashed_password_bytes = unsafe {
        assert!(!hashed_password.is_null());
        CStr::from_ptr(hashed_password)
    }.to_bytes().to_vec();
    match CASArgon::derive_aes_256_key(hashed_password_bytes) {
        Ok(key) => {
            let key_ptr = unsafe {
                let ptr = libc::malloc(key.len()) as *mut u8;
                std::ptr::copy_nonoverlapping(key.as_ptr(), ptr, key.len());
                ptr
            };
            Argon2KDFAes128 {
                key: key_ptr,
                length: key.len(),
                error_code: 0,
            }
        }
        Err(e) => Argon2KDFAes128 {
            key: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

#[no_mangle]
pub extern "C" fn argon2_verify(hashed_pass: *const c_char, password: *const c_char) -> CasVerifyResult {
    let hashed_password = unsafe {
        assert!(!hashed_pass.is_null());
        CStr::from_ptr(hashed_pass)
    }
    .to_str()
    .unwrap()
    .to_string();

    let password_to_verify = unsafe {
        assert!(!password.is_null());
        CStr::from_ptr(password)
    }
    .to_str()
    .unwrap()
    .to_string();
    match CASArgon::verify_password(hashed_password, password_to_verify) {
        Ok(is_valid) => CasVerifyResult { is_valid, error_code: 0 },
        Err(e) => CasVerifyResult { is_valid: false, error_code: cas_error_code(&e) },
    }
}

#[test]
fn argon2_verify_test() {
    let password = "PasswordToVerify";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password = argon2_hash(password_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password.value) };
    let hashed_password_bytes = hashed_password_ctr.as_bytes_with_nul();
    let hashed_password_ptr = hashed_password_bytes.as_ptr() as *const i8;
    let is_valid = argon2_verify(hashed_password_ptr, password_ptr);
    assert_eq!(true, is_valid.is_valid);
}

#[no_mangle]
pub extern "C" fn argon2_hash(pass_to_hash: *const c_char) -> CasStringResult {
    let password = unsafe {
        assert!(!pass_to_hash.is_null());
        CStr::from_ptr(pass_to_hash)
    }
    .to_str()
    .unwrap()
    .to_string();
    match CASArgon::hash_password(password) {
        Ok(new_hash) => CasStringResult { value: CString::new(new_hash).unwrap().into_raw(), error_code: 0 },
        Err(e) => CasStringResult { value: std::ptr::null_mut(), error_code: cas_error_code(&e) },
    }
}

#[test]
fn argon2_hash_test() {
    let password = "DontUseThisPassword";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password_ptr = argon2_hash(password_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password_ptr.value) };
    let hashed_password_str = hashed_password_ctr.to_str().unwrap();
    assert_ne!(password, hashed_password_str);
}