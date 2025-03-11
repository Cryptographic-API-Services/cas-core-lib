use std::ffi::{c_char, CStr, CString};
use cas_lib::password_hashers::argon2::CASArgon;

use super::types::Argon2KDFAes128;

#[no_mangle]
pub extern "C" fn argon2_derive_aes_128_key(hashed_password: *const c_char) -> [u8] {
    let hashed_password_bytes = unsafe {
        assert!(!hashed_password.is_null());
        CStr::from_ptr(hashed_password)
    }
    .to_str()
    .unwrap()
    .as_bytes();
    let key: [u8; 16] = CASArgon::derive_aes_128_key(hashed_password_bytes);
    let key_ptr = unsafe {
        let ptr = libc::malloc(key.len()) as *mut u8;
        std::ptr::copy_nonoverlapping(key.as_ptr(), ptr, key.len());
        ptr
    };
    let result = Argon2KDFAes128 {
        key: key_ptr,
        length: key.len()
    };
    result
}

#[no_mangle]
pub extern "C" fn argon2_derive_aes_256_key(hashed_password: *const c_char) -> Argon2KDFAes128 {
    let hashed_password_bytes = unsafe {
        assert!(!hashed_password.is_null());
        CStr::from_ptr(hashed_password)
    }
    .to_str()
    .unwrap()
    .as_bytes();
    let key: [u8; 32] = CASArgon::derive_aes_256_key(hashed_password_bytes);
    let key_ptr = unsafe {
        let ptr = libc::malloc(key.len()) as *mut u8;
        std::ptr::copy_nonoverlapping(key.as_ptr(), ptr, key.len());
        ptr
    };
    let result = Argon2KDFAes128 {
        key: key_ptr,
        length: key.len()
    };
    result
}

#[no_mangle]
pub extern "C" fn argon2_verify(hashed_pass: *const c_char, password: *const c_char) -> bool {
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
    return CASArgon::verify_password(hashed_password, password_to_verify);
}

#[test]
fn argon2_verify_test() {
    let password = "PasswordToVerify";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password = argon2_hash(password_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password) };
    let hashed_password_bytes = hashed_password_ctr.as_bytes_with_nul();
    let hashed_password_ptr = hashed_password_bytes.as_ptr() as *const i8;
    let is_valid = argon2_verify(hashed_password_ptr, password_ptr);
    assert_eq!(true, is_valid);
}

#[no_mangle]
pub extern "C" fn argon2_verify_threadpool(hashed_pass: *const c_char, password: *const c_char) -> bool {
    let hashed_pass_string = unsafe {
        assert!(!hashed_pass.is_null());
        CStr::from_ptr(hashed_pass)
    }
    .to_str()
    .unwrap()
    .to_string();

    let password_string = unsafe {
        assert!(!password.is_null());
        CStr::from_ptr(password)
    }
    .to_str()
    .unwrap()
    .to_string();
    let result: bool = CASArgon::verify_password_threadpool(hashed_pass_string, password_string);
    result
}

#[test]
fn argon2_verify_threadpool_test() {
    let password = "PasswordToVerify";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password = argon2_hash_threadpool(password_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password) };
    let hashed_password_bytes = hashed_password_ctr.as_bytes_with_nul();
    let hashed_password_ptr = hashed_password_bytes.as_ptr() as *const i8;
    let is_valid = argon2_verify_threadpool(hashed_password_ptr, password_ptr);
    assert_eq!(true, is_valid);
}

#[no_mangle]
pub extern "C" fn argon2_hash(pass_to_hash: *const c_char) -> *mut c_char {
    let password = unsafe {
        assert!(!pass_to_hash.is_null());
        CStr::from_ptr(pass_to_hash)
    }
    .to_str()
    .unwrap()
    .to_string();
    let new_hash = CASArgon::hash_password(password);
    let password_hash = CString::new(new_hash).unwrap().into_raw();
    return password_hash;
}

#[test]
fn argon2_hash_test() {
    let password = "DontUseThisPassword";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password_ptr = argon2_hash(password_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password_ptr) };
    let hashed_password_str = hashed_password_ctr.to_str().unwrap();
    assert_ne!(password, hashed_password_str);
}

#[no_mangle]
pub extern "C" fn argon2_hash_threadpool(pass_to_hash: *const c_char) -> *mut c_char {
    let password = unsafe {
        assert!(!pass_to_hash.is_null());
        CStr::from_ptr(pass_to_hash)
    }
    .to_str()
    .unwrap()
    .to_string();
    let new_hash = CASArgon::hash_password_threadpool(password);
    let result = CString::new(new_hash).unwrap().into_raw();
    result
}

#[test]
fn argon2_hash_threadpool_test() {
    let password = "DontUseThisPassword";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password_ptr = argon2_hash_threadpool(password_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password_ptr) };
    let hashed_password_str = hashed_password_ctr.to_str().unwrap();
    assert_ne!(password, hashed_password_str);
}