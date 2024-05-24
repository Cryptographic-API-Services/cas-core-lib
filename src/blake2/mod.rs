use std::{ffi::c_uchar, sync::mpsc};

use cas_lib::hashers::{blake2::CASBlake2, cas_hasher::CASHasher};

mod types;
use self::types::Blake2HashByteResult;

#[no_mangle]
pub extern "C" fn blake2_512_bytes(
    data: *const c_uchar,
    data_length: usize,
) -> Blake2HashByteResult {
    let data_slice = unsafe {
        assert!(!data.is_null());
        std::slice::from_raw_parts(data, data_length)
    }
    .to_vec();

    let mut result: Vec<u8> = <CASBlake2 as CASHasher>::hash_512(data_slice);
    let capacity = result.capacity();
    result.reserve_exact(capacity);
    let return_result = Blake2HashByteResult {
        result_bytes_ptr: result.as_mut_ptr(),
        length: result.len(),
    };
    std::mem::forget(result);
    return_result
}

#[no_mangle]
pub extern "C" fn blake2_512_bytes_threadpool(
    data: *const c_uchar,
    data_length: usize,
) -> Blake2HashByteResult {
    let data_slice = unsafe {
        assert!(!data.is_null());
        std::slice::from_raw_parts(data, data_length)
    }
    .to_vec();
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let thread_result: Vec<u8> = <CASBlake2 as CASHasher>::hash_512(data_slice);
        sender.send(thread_result);
    });
    let mut result = receiver.recv().unwrap();
    let capacity = result.capacity();
    result.reserve_exact(capacity);
    let return_result = Blake2HashByteResult {
        result_bytes_ptr: result.as_mut_ptr(),
        length: result.len(),
    };
    std::mem::forget(result);
    return_result
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
    }
    .to_vec();
    let to_compare_slice = unsafe {
        assert!(!to_compare.is_null());
        std::slice::from_raw_parts(to_compare, to_compare_length)
    }
    .to_vec();
    return <CASBlake2 as CASHasher>::verify_512(data_slice, to_compare_slice);
}

#[no_mangle]
pub extern "C" fn blake2_512_bytes_verify_threadpool(
    hashed_data: *const c_uchar,
    hashed_data_length: usize,
    to_compare: *const c_uchar,
    to_compare_length: usize,
) -> bool {
    let data_slice = unsafe {
        assert!(!hashed_data.is_null());
        std::slice::from_raw_parts(hashed_data, hashed_data_length)
    }
    .to_vec();
    let to_compare_slice = unsafe {
        assert!(!to_compare.is_null());
        std::slice::from_raw_parts(to_compare, to_compare_length)
    }
    .to_vec();
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let thread_result: bool =
            <CASBlake2 as CASHasher>::verify_512(data_slice, to_compare_slice);
        sender.send(thread_result);
    });
    let result = receiver.recv().unwrap();
    result
}

#[no_mangle]
pub extern "C" fn blake2_256_bytes(
    data_to_hash: *const c_uchar,
    data_to_hash_length: usize,
) -> Blake2HashByteResult {
    let data_to_hash_slice = unsafe {
        assert!(!data_to_hash.is_null());
        std::slice::from_raw_parts(data_to_hash, data_to_hash_length)
    }
    .to_vec();
    let mut result = <CASBlake2 as CASHasher>::hash_256(data_to_hash_slice);
    let capacity = result.capacity();
    result.reserve_exact(capacity);
    let return_result = Blake2HashByteResult {
        result_bytes_ptr: result.as_mut_ptr(),
        length: result.len(),
    };
    std::mem::forget(result);
    return return_result
}

#[no_mangle]
pub extern "C" fn blake2_256_bytes_threadpool(
    data_to_hash: *const c_uchar,
    data_to_hash_length: usize,
) -> Blake2HashByteResult {
    let data_to_hash_slice = unsafe {
        assert!(!data_to_hash.is_null());
        std::slice::from_raw_parts(data_to_hash, data_to_hash_length)
    }
    .to_vec();
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let result = <CASBlake2 as CASHasher>::hash_256(data_to_hash_slice);
        sender.send(result);
    });
    let mut result = receiver.recv().unwrap();
    let capacity = result.capacity();
    result.reserve_exact(capacity);
    let return_result = Blake2HashByteResult {
        result_bytes_ptr: result.as_mut_ptr(),
        length: result.len(),
    };
    std::mem::forget(result);
    return_result
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
    }
    .to_vec();
    let to_compare_slice = unsafe {
        assert!(!to_compare.is_null());
        std::slice::from_raw_parts(to_compare, to_compare_length)
    }
    .to_vec();
    let result = <CASBlake2 as CASHasher>::verify_256(data_slice, to_compare_slice);
    result
}

#[no_mangle]
pub extern "C" fn blake2_256_bytes_verify_threadpool(
    hashed_data: *const c_uchar,
    hashed_data_length: usize,
    to_compare: *const c_uchar,
    to_compare_length: usize,
) -> bool {
    let data_slice = unsafe {
        assert!(!hashed_data.is_null());
        std::slice::from_raw_parts(hashed_data, hashed_data_length)
    }
    .to_vec();
    let to_compare_slice = unsafe {
        assert!(!to_compare.is_null());
        std::slice::from_raw_parts(to_compare, to_compare_length)
    }
    .to_vec();
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let result = <CASBlake2 as CASHasher>::verify_256(data_slice, to_compare_slice);
        sender.send(result);
    });
    let result = receiver.recv().unwrap();
    result
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
