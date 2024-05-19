use std::{
    ffi::{c_char, CStr, CString}, sync::mpsc
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use cas_lib::password_hashers::{argon2::CASArgon, cas_password_hasher::CASPasswordHasher};

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
    return <CASArgon as CASPasswordHasher>::verify_password(hashed_password, password_to_verify);
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

#[test]
fn argon2_verify_fail_test() {
    let password = "PasswordToVerify";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password = argon2_hash(password_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password) };
    let hashed_password_bytes = hashed_password_ctr.as_bytes_with_nul();
    let hashed_password_ptr = hashed_password_bytes.as_ptr() as *const i8;
    let bad_password = CString::new("NotTheFirstPassword")
        .unwrap()
        .as_bytes_with_nul()
        .as_ptr() as *const i8;
    let is_valid = argon2_verify(hashed_password_ptr, bad_password);
    assert_eq!(false, is_valid);
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
    let result: bool = <CASArgon as CASPasswordHasher>::verify_password_threadpool(hashed_pass_string, password_string);
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
    let new_hash = <CASArgon as CASPasswordHasher>::hash_password(password);
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
    let new_hash = <CASArgon as CASPasswordHasher>::hash__password_threadpool(password);
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