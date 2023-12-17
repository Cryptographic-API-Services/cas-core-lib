use core::slice;
use std::ffi::{c_char, c_uchar, CStr, CString};

use sha3::{Digest, Sha3_256, Sha3_512};

#[repr(C)]
pub struct SHAHashByteResult {
    pub result_bytes_ptr: *mut c_uchar,
    pub length: usize,
}

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

#[test]
fn sha512_hash() {
    let data_to_hash = "Hello World";
    let data_to_hash_ptr = CString::new(data_to_hash).unwrap().into_raw();
    let result = sha512(data_to_hash_ptr);
    let result_string = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
    assert_ne!(data_to_hash, result_string);
}

#[no_mangle]
pub extern "C" fn sha512_bytes(data_to_hash: *const c_uchar, data_len: usize) -> SHAHashByteResult {
    assert!(!data_to_hash.is_null());
    let data_to_hash_slice = unsafe { std::slice::from_raw_parts(data_to_hash, data_len) };
    let mut hasher = Sha3_512::new();
    hasher.update(data_to_hash_slice);
    let result = hasher.finalize();
    return unsafe {
        let size_of_result = std::mem::size_of_val(&result);
        let result_raw_ptr = libc::malloc(size_of_result) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(result.as_ptr(), result_raw_ptr, size_of_result);
        let result = SHAHashByteResult {
            result_bytes_ptr: result_raw_ptr,
            length: size_of_result
        };
        result
    };
}

#[test]
fn sha512_bytes_test() {
    let data_to_hash = "This is a test hash";
    let data_to_hash_bytes = data_to_hash.as_bytes();
    let data_to_hash_length: usize = data_to_hash_bytes.len();
    let data_to_hash_bytes_ptr = data_to_hash_bytes.as_ptr();
    let result = sha512_bytes(data_to_hash_bytes_ptr, data_to_hash_length);
    let result_slice = unsafe { slice::from_raw_parts(result, data_to_hash_length) };
    assert_ne!(data_to_hash_bytes, result_slice);
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
fn sha256_hash() {
    let data_to_hash = "Hello World";
    let data_to_hash_ptr = CString::new(data_to_hash).unwrap().into_raw();
    let result = sha256(data_to_hash_ptr);
    let result_string = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
    assert_ne!(data_to_hash, result_string);
}

#[no_mangle]
pub extern "C" fn sha256_bytes(data_to_hash: *const c_uchar, data_len: usize) -> SHAHashByteResult {
    assert!(!data_to_hash.is_null());
    let data_to_hash_slice = unsafe { std::slice::from_raw_parts(data_to_hash, data_len) };
    let mut hasher = Sha3_256::new();
    hasher.update(data_to_hash_slice);
    let result = hasher.finalize();
    return unsafe {
        let size_of_result = std::mem::size_of_val(&result);
        let result_raw_ptr = libc::malloc(size_of_result) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(result.as_ptr(), result_raw_ptr, size_of_result);
        let result = SHAHashByteResult {
            result_bytes_ptr: result_raw_ptr,
            length: size_of_result
        };
        result
    };
}

#[test]
fn sha256_bytes_test() {
    let data_to_hash = "This is a test hash for SHA 256";
    let data_to_hash_bytes = data_to_hash.as_bytes();
    let data_to_hash_length: usize = data_to_hash_bytes.len();
    let data_to_hash_bytes_ptr = data_to_hash_bytes.as_ptr();
    let result = sha256_bytes(data_to_hash_bytes_ptr, data_to_hash_length);
    let result_slice = unsafe { slice::from_raw_parts(result, data_to_hash_length) };
    assert_ne!(data_to_hash_bytes, result_slice);
}
