use std::ffi::{c_char, c_uchar, CStr, CString};

use blake2::{Blake2b512, Blake2s256, Digest};

#[repr(C)]
pub struct Blake2HashByteResult {
    pub result_bytes_ptr: *mut c_uchar,
    pub length: usize,
}

#[no_mangle]
pub extern "C" fn blake2_512(data: *const c_char) -> *mut c_char {
    let data_bytes = unsafe {
        assert!(!data.is_null());

        CStr::from_ptr(data)
    }
    .to_bytes();

    let mut hasher = Blake2b512::new();
    hasher.update(data_bytes);
    let result = hasher.finalize();
    return CString::new(base64::encode(result)).unwrap().into_raw();
}

#[test]
fn blake2_512_test() {
    let password = "PasswordToHash";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let passsword_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password = blake2_512(passsword_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password) };
    let hashed_password_str = hashed_password_ctr.to_str().unwrap();
    assert_ne!(hashed_password_str, password);
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
pub extern "C" fn blake2_512_verify(data: *const c_char, hash: *const c_char) -> bool {
    let data_bytes = unsafe {
        assert!(!data.is_null());

        CStr::from_ptr(data)
    }
    .to_bytes();

    let hash_str = unsafe {
        assert!(!hash.is_null());

        CStr::from_ptr(hash)
    }
    .to_str()
    .unwrap();

    let mut hasher = Blake2b512::new();
    hasher.update(data_bytes);
    let result = hasher.finalize();
    let result_str = base64::encode(result);
    return result_str == hash_str;
}

#[test]
fn blake2_512_verify_test() {
    let password = "PasswordToHash";
    let password_to_verify = "PasswordToHash";
    let password_cstr = CString::new(password).unwrap();
    let password_to_verify_cstr = CString::new(password_to_verify).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_to_verify_bytes = password_to_verify_cstr.as_bytes_with_nul();
    let passsword_ptr = password_bytes.as_ptr() as *const i8;
    let password_to_verify_ptr = password_to_verify_bytes.as_ptr() as *const i8;
    let hashed_password = blake2_512(passsword_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password) };
    let hashed_password_str = hashed_password_ctr.to_str().unwrap();
    let verification_reuslt = blake2_512_verify(
        password_to_verify_ptr,
        hashed_password_str.as_ptr() as *const i8,
    );
    assert_eq!(verification_reuslt, true);
}

#[no_mangle]
pub extern "C" fn blake2_256(data: *const c_char) -> *mut c_char {
    let data_bytes = unsafe {
        assert!(!data.is_null());

        CStr::from_ptr(data)
    }
    .to_bytes();

    let mut hasher = Blake2s256::new();
    hasher.update(data_bytes);
    let result = hasher.finalize();
    return CString::new(base64::encode(result)).unwrap().into_raw();
}

#[test]
fn blake2_256_test() {
    let password = "PasswordToHash";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let passsword_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password = blake2_256(passsword_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password) };
    let hashed_password_str = hashed_password_ctr.to_str().unwrap();
    assert_ne!(hashed_password_str, password);
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
pub extern "C" fn blake2_256_verify(data: *const c_char, hash: *const c_char) -> bool {
    let data_bytes = unsafe {
        assert!(!data.is_null());

        CStr::from_ptr(data)
    }
    .to_bytes();

    let hash_str = unsafe {
        assert!(!hash.is_null());

        CStr::from_ptr(hash)
    }
    .to_str()
    .unwrap();

    let mut hasher = Blake2s256::new();
    hasher.update(data_bytes);
    let result = hasher.finalize();
    let result_str = base64::encode(result);
    return result_str == hash_str;
}

#[test]
fn blake2_256_verify_test() {
    let password = "PasswordToHash";
    let password_to_verify = "PasswordToHash";
    let password_cstr = CString::new(password).unwrap();
    let password_to_verify_cstr = CString::new(password_to_verify).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_to_verify_bytes = password_to_verify_cstr.as_bytes_with_nul();
    let passsword_ptr = password_bytes.as_ptr() as *const i8;
    let password_to_verify_ptr = password_to_verify_bytes.as_ptr() as *const i8;
    let hashed_password = blake2_256(passsword_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password) };
    let hashed_password_str = hashed_password_ctr.to_str().unwrap();
    let verification_reuslt = blake2_256_verify(
        password_to_verify_ptr,
        hashed_password_str.as_ptr() as *const i8,
    );
    assert_eq!(verification_reuslt, true);
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
