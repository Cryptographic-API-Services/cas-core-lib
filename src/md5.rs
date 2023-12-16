use std::ffi::{c_char, CStr, CString};

use md5::{Digest, Md5};

use crate::sha::sha512;

#[no_mangle]
pub extern "C" fn md5_hash_string(to_hash: *const c_char) -> *mut c_char {
    let string_to_hash = unsafe {
        assert!(!to_hash.is_null());

        CStr::from_ptr(to_hash)
    }
    .to_str()
    .unwrap()
    .as_bytes();
    let mut hasher = Md5::new();
    hasher.update(string_to_hash);
    let result = hasher.finalize();
    return CString::new(format!("{:x}", result)).unwrap().into_raw();
}

#[test]
fn md5_hash_string_test() {
    let string_to_hash = "Test MD5 Hash";
    let string_to_hash_ptr = CString::new(string_to_hash).unwrap().into_raw();
    let result = md5_hash_string(string_to_hash_ptr);
    let result_string = unsafe {CStr::from_ptr(result)}.to_str().unwrap();
    assert_ne!(result_string, string_to_hash);
}

#[no_mangle]
pub extern "C" fn md5_hash_verify(hash_to_verify: *const c_char, to_hash: *const c_char) -> bool {
    let string_to_hash = unsafe {
        assert!(!to_hash.is_null());

        CStr::from_ptr(to_hash)
    }
    .to_str()
    .unwrap()
    .as_bytes();
    let hash_to_verify = unsafe {
        assert!(!hash_to_verify.is_null());

        CStr::from_ptr(hash_to_verify)
    }
    .to_str()
    .unwrap();
    let mut hasher = Md5::new();
    hasher.update(string_to_hash);
    let result = hasher.finalize();
    return hash_to_verify.eq(&format!("{:x}", result));
}

#[test]
fn md5_hash_verify_test() {
    let string_to_hash = "Test MD5 Hash";
    let string_to_hash_ptr = CString::new(string_to_hash).unwrap().into_raw();
    let result = md5_hash_string(string_to_hash_ptr);
    let is_verified = md5_hash_verify(result, string_to_hash_ptr);
    assert_eq!(is_verified, true);
}
