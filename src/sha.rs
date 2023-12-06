use std::{
    ffi::{c_char, CStr, CString}
};

use sha3::{Digest, Sha3_256, Sha3_512};

#[no_mangle]
pub extern "C" fn sha512(data_to_hash: *const c_char) -> *mut c_char {
    let data_to_hash_bytes = unsafe {
        assert!(!data_to_hash.is_null());
        CStr::from_ptr(data_to_hash)
    }
    .to_str()
    .unwrap()
    .as_bytes();
    let mut hasher = Sha3_512::new();
    hasher.update(data_to_hash_bytes);
    let result = hasher.finalize();
    return CString::new(base64::encode(result)).unwrap().into_raw();
}

#[no_mangle]
pub extern "C" fn sha256(data_to_hash: *const c_char) -> *mut c_char {
    let data_to_hash_bytes = unsafe {
        assert!(!data_to_hash.is_null());
        CStr::from_ptr(data_to_hash)
    }
    .to_str()
    .unwrap()
    .as_bytes();
    let mut hasher = Sha3_256::new();
    hasher.update(data_to_hash_bytes);
    let result = hasher.finalize();
    return CString::new(base64::encode(result)).unwrap().into_raw();
}

#[test]
fn sha512_hash() {
    let data_to_hash = "Hello World";
    let data_to_hash_ptr = CString::new(data_to_hash).unwrap().into_raw();
    let result = sha512(data_to_hash_ptr);
    let result_string = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
    assert_ne!(data_to_hash, result_string);
}

#[test]
fn sha256_hash() {
    let data_to_hash = "Hello World";
    let data_to_hash_ptr = CString::new(data_to_hash).unwrap().into_raw();
    let result = sha256(data_to_hash_ptr);
    let result_string = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
    assert_ne!(data_to_hash, result_string);
}
