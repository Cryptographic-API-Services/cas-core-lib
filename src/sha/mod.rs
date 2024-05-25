use core::slice;
use std::{ffi::c_uchar, sync::mpsc};

use cas_lib::hashers::{cas_hasher::CASHasher, sha::CASSHA};
use sha3::{Digest, Sha3_256, Sha3_512};

use self::types::SHAHashByteResult;
mod types;

#[no_mangle]
pub extern "C" fn sha512_bytes(data_to_hash: *const c_uchar, data_len: usize) -> SHAHashByteResult {
    assert!(!data_to_hash.is_null());
    let data_to_hash_slice = unsafe { std::slice::from_raw_parts(data_to_hash, data_len) }.to_vec();
    let mut result = <CASSHA as CASHasher>::hash_512(data_to_hash_slice);
    let capacity = result.capacity();
    result.reserve_exact(capacity);
    let return_result = SHAHashByteResult {
        result_bytes_ptr: result.as_mut_ptr(),
        length: result.len(),
    };
    std::mem::forget(result);
    return_result
}

#[no_mangle]
pub extern "C" fn sha512_bytes_threadpool(
    data_to_hash: *const c_uchar,
    data_len: usize,
) -> SHAHashByteResult {
    assert!(!data_to_hash.is_null());
    let data_to_hash_slice = unsafe { std::slice::from_raw_parts(data_to_hash, data_len) }.to_vec();
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let mut result = <CASSHA as CASHasher>::hash_512(data_to_hash_slice);
        sender.send(result);
    });
    let mut result = receiver.recv().unwrap();
    let capacity = result.capacity();
    result.reserve_exact(capacity);
    let return_result = SHAHashByteResult {
        result_bytes_ptr: result.as_mut_ptr(),
        length: result.len(),
    };
    std::mem::forget(result);
    return_result
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
    let data_to_hash_slice = unsafe { std::slice::from_raw_parts(data_to_hash, data_len) }.to_vec();
    let data_to_verify_slice =
        unsafe { std::slice::from_raw_parts(data_to_verify, data_to_verify_len) }.to_vec();
    let result = <CASSHA as CASHasher>::verify_512(data_to_verify_slice, data_to_hash_slice);
    result
}

#[no_mangle]
pub extern "C" fn sha512_bytes_verify_threadpool(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> bool {
    assert!(!data_to_hash.is_null());
    assert!(!data_to_verify.is_null());
    let data_to_hash_slice = unsafe { std::slice::from_raw_parts(data_to_hash, data_len) }.to_vec();
    let data_to_verify_slice =
        unsafe { std::slice::from_raw_parts(data_to_verify, data_to_verify_len) }.to_vec();
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let result = <CASSHA as CASHasher>::verify_512(data_to_verify_slice, data_to_hash_slice);
        sender.send(result);
    });
    let result = receiver.recv().unwrap();
    result
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
    let data_to_hash_slice = unsafe { std::slice::from_raw_parts(data_to_hash, data_len) }.to_vec();
    let mut result = <CASSHA as CASHasher>::hash_256(data_to_hash_slice);
    let capacity = result.capacity();
    result.reserve_exact(capacity);
    let return_result = SHAHashByteResult {
        result_bytes_ptr: result.as_mut_ptr(),
        length: result.len(),
    };
    std::mem::forget(result);
    return_result
}

#[no_mangle]
pub extern "C" fn sha256_bytes_threadpool(
    data_to_hash: *const c_uchar,
    data_len: usize,
) -> SHAHashByteResult {
    assert!(!data_to_hash.is_null());
    let data_to_hash_slice = unsafe { std::slice::from_raw_parts(data_to_hash, data_len) }.to_vec();
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let mut result = <CASSHA as CASHasher>::hash_256(data_to_hash_slice);
        sender.send(result);
    });
    let mut result = receiver.recv().unwrap();
    let capacity = result.capacity();
    result.reserve_exact(capacity);
    let return_result = SHAHashByteResult {
        result_bytes_ptr: result.as_mut_ptr(),
        length: result.len(),
    };
    std::mem::forget(result);
    return_result
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
    let data_to_hash_slice = unsafe { std::slice::from_raw_parts(data_to_hash, data_len) }.to_vec();
    let data_to_verify_slice =
        unsafe { std::slice::from_raw_parts(data_to_verify, data_to_verify_len) }.to_vec();
    let result = <CASSHA as CASHasher>::verify_256(data_to_verify_slice, data_to_hash_slice);
    result
}

#[no_mangle]
pub extern "C" fn sha256_bytes_verify_threadpool(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> bool {
    assert!(!data_to_hash.is_null());
    assert!(!data_to_verify.is_null());
    let data_to_hash_slice = unsafe { std::slice::from_raw_parts(data_to_hash, data_len) }.to_vec();
    let data_to_verify_slice =
        unsafe { std::slice::from_raw_parts(data_to_verify, data_to_verify_len) }.to_vec();
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let result = <CASSHA as CASHasher>::verify_256(data_to_verify_slice, data_to_hash_slice);
        sender.send(result);
    });
    let result = receiver.recv().unwrap();
    result
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
