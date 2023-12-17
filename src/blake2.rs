use std::ffi::{c_char, CStr, CString};

use blake2::{Blake2b512, Blake2s256, Digest};

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
