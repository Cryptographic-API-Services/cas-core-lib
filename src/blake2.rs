use core::slice;
use std::ffi::c_uchar;

use blake2::{Blake2b512, Blake2s256, Digest};

#[repr(C)]
pub struct Blake2HashByteResult {
    pub result_bytes_ptr: *mut c_uchar,
    pub length: usize,
}

#[no_mangle]
pub extern "C" fn blake2_512_bytes(
    data: *const c_uchar,
    data_length: usize,
) -> Blake2HashByteResult {
    let data_slice = unsafe {
        assert!(!data.is_null());
        std::slice::from_raw_parts(data, data_length)
    };

    let mut hasher = Blake2b512::new();
    hasher.update(data_slice);
    let result = hasher.finalize();
    return unsafe {
        let size_of_result = std::mem::size_of_val(&result);
        let result_raw_ptr = libc::malloc(size_of_result) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(result.as_ptr(), result_raw_ptr, size_of_result);
        let result = Blake2HashByteResult {
            result_bytes_ptr: result_raw_ptr,
            length: size_of_result,
        };
        result
    };
}

#[test]
fn blake2_512_bytes_test() {
    let data_to_hash = "Blake2512HashingTechnique";
    let data_to_hash_bytes = data_to_hash.as_bytes();
    let data_to_hash_length = data_to_hash_bytes.len();
    let result = blake2_512_bytes(data_to_hash_bytes.as_ptr(), data_to_hash_length);
    let result_slice = unsafe { slice::from_raw_parts(result.result_bytes_ptr, result.length) };
    assert_ne!(data_to_hash_bytes, result_slice);
}

#[no_mangle]
pub extern "C" fn blake2_512_bytes_verify(
    hashed_data: *const c_uchar,
    hashed_data_length: usize,
    to_compare: *const c_uchar,
    to_compare_length: usize,
) -> bool {
    let data_slice = unsafe {
        assert!(!hashed_data.is_null());
        std::slice::from_raw_parts(hashed_data, hashed_data_length)
    };
    let to_compare_slice = unsafe {
        assert!(!to_compare.is_null());
        std::slice::from_raw_parts(to_compare, to_compare_length)
    };
    let mut hasher = Blake2b512::new();
    hasher.update(to_compare_slice);
    let result = hasher.finalize();
    let result_slice: &[u8] = result.as_ref();
    return result_slice.eq(data_slice);
}

#[no_mangle]
pub extern "C" fn blake2_256_bytes(
    data_to_hash: *const c_uchar,
    data_to_hash_length: usize,
) -> Blake2HashByteResult {
    let data_to_hash_slice = unsafe {
        assert!(!data_to_hash.is_null());
        std::slice::from_raw_parts(data_to_hash, data_to_hash_length)
    };
    let mut hasher = Blake2s256::new();
    hasher.update(data_to_hash_slice);
    let result = hasher.finalize();
    return unsafe {
        let size_of_result = std::mem::size_of_val(&result);
        let result_raw_ptr = libc::malloc(size_of_result) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(result.as_ptr(), result_raw_ptr, size_of_result);
        let result = Blake2HashByteResult {
            result_bytes_ptr: result_raw_ptr,
            length: size_of_result,
        };
        result
    };
}

#[test]
fn blake2_256_bytes_test() {
    let data_to_hash = "Blake2256HashingTechnique";
    let data_to_hash_bytes = data_to_hash.as_bytes();
    let data_to_hash_length = data_to_hash_bytes.len();
    let result: Blake2HashByteResult =
        blake2_256_bytes(data_to_hash_bytes.as_ptr(), data_to_hash_length);
    let result_slice = unsafe { slice::from_raw_parts(result.result_bytes_ptr, result.length) };
    assert_ne!(data_to_hash_bytes, result_slice);
}

#[no_mangle]
pub extern "C" fn blake2_256_bytes_verify(
    hashed_data: *const c_uchar,
    hashed_data_length: usize,
    to_compare: *const c_uchar,
    to_compare_length: usize,
) -> bool {
    let data_slice = unsafe {
        assert!(!hashed_data.is_null());
        std::slice::from_raw_parts(hashed_data, hashed_data_length)
    };
    let to_compare_slice = unsafe {
        assert!(!to_compare.is_null());
        std::slice::from_raw_parts(to_compare, to_compare_length)
    };
    let mut hasher = Blake2s256::new();
    hasher.update(to_compare_slice);
    let result = hasher.finalize();
    let result_slice: &[u8] = result.as_ref();
    return result_slice.eq(data_slice);
}

#[test]
fn blake2_256_bytes_verify_test() {
    let data_to_hash = "Blake2512HashingTechnique";
    let data_to_hash_bytes = data_to_hash.as_bytes();
    let data_to_hash_length = data_to_hash_bytes.len();
    let result: Blake2HashByteResult =
        blake2_256_bytes(data_to_hash_bytes.as_ptr(), data_to_hash_length);
    let result_slice = unsafe { slice::from_raw_parts(result.result_bytes_ptr, result.length) };
    assert_ne!(data_to_hash_bytes, result_slice);
}
