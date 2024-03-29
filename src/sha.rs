use core::slice;
use std::ffi::c_uchar;

use sha3::{Digest, Sha3_256, Sha3_512};

#[repr(C)]
pub struct SHAHashByteResult {
    pub result_bytes_ptr: *mut c_uchar,
    pub length: usize,
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
            length: size_of_result,
        };
        result
    };
}

#[no_mangle]
pub extern "C" fn sha512_bytes_verify(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> bool {
    assert!(!data_to_hash.is_null());
    assert!(!data_to_verify.is_null());
    let data_to_hash_slice = unsafe { std::slice::from_raw_parts(data_to_hash, data_len) };
    let data_to_verify_slice = unsafe {std::slice::from_raw_parts(data_to_verify, data_to_verify_len)};
    let mut hasher = Sha3_512::new();
    hasher.update(data_to_hash_slice);
    let result = hasher.finalize();
    let result_slice = result.as_slice();
    return data_to_verify_slice.eq(result_slice);
}

#[test]
fn sha512_bytes_test() {
    let data_to_hash = "This is a test hash";
    let data_to_hash_bytes = data_to_hash.as_bytes();
    let data_to_hash_length: usize = data_to_hash_bytes.len();
    let data_to_hash_bytes_ptr = data_to_hash_bytes.as_ptr();
    let result = sha512_bytes(data_to_hash_bytes_ptr, data_to_hash_length);
    let result_slice = unsafe { slice::from_raw_parts(result.result_bytes_ptr, result.length) };
    assert_ne!(data_to_hash_bytes, result_slice);
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
            length: size_of_result,
        };
        result
    };
}

#[no_mangle]
pub extern "C" fn sha256_bytes_verify(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> bool {
    assert!(!data_to_hash.is_null());
    assert!(!data_to_verify.is_null());
    let data_to_hash_slice = unsafe { std::slice::from_raw_parts(data_to_hash, data_len) };
    let data_to_verify_slice = unsafe {std::slice::from_raw_parts(data_to_verify, data_to_verify_len)};
    let mut hasher = Sha3_256::new();
    hasher.update(data_to_hash_slice);
    let result = hasher.finalize();
    let result_slice = result.as_slice();
    return data_to_verify_slice.eq(result_slice);
}

#[test]
fn sha256_bytes_test() {
    let data_to_hash = "This is a test hash for SHA 256";
    let data_to_hash_bytes = data_to_hash.as_bytes();
    let data_to_hash_length: usize = data_to_hash_bytes.len();
    let data_to_hash_bytes_ptr = data_to_hash_bytes.as_ptr();
    let result = sha256_bytes(data_to_hash_bytes_ptr, data_to_hash_length);
    let result_slice = unsafe { slice::from_raw_parts(result.result_bytes_ptr, result.length) };
    assert_ne!(data_to_hash_bytes, result_slice);
}
