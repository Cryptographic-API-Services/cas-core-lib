use std::ffi::{c_char, CStr, CString};
use cas_lib::password_hashers::{scrypt::CASScrypt};


#[no_mangle]
pub extern "C" fn scrypt_hash_with_parameters(
    pass_to_hash: *const c_char,
    cpu_memory_cost: u8,
    block_size: u32,
    parallelism: u32,
) -> *mut c_char {
    let string_pass = unsafe {
        assert!(!pass_to_hash.is_null());

        CStr::from_ptr(pass_to_hash)
    }
    .to_str()
    .unwrap()
    .to_string();
    let new_hash = CASScrypt::hash_password_customized(string_pass, cpu_memory_cost, block_size, parallelism);
    return CString::new(new_hash).unwrap().into_raw();
}

#[no_mangle]
pub extern "C" fn scrypt_hash(pass_to_hash: *const c_char) -> *mut c_char {
    let string_pass = unsafe {
        assert!(!pass_to_hash.is_null());

        CStr::from_ptr(pass_to_hash)
    }
    .to_str()
    .unwrap()
    .to_string();
    let new_hash = CASScrypt::hash_password(string_pass);
    return CString::new(new_hash).unwrap().into_raw();
}

#[test]
fn scrypt_hash_test() {
    let password = "PasswordToTest";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed = scrypt_hash(password_ptr);
    let hashed_ctr = unsafe { CString::from_raw(hashed) };
    let hashed_str = hashed_ctr.to_str().unwrap();
    assert_ne!(hashed_str, password);
}

#[no_mangle]
pub extern "C" fn scrypt_verify(
    hash_to_check: *const c_char,
    pass_to_check: *const c_char,
) -> bool {
    let string_hash = unsafe {
        assert!(!hash_to_check.is_null());
    
        CStr::from_ptr(hash_to_check)
    }
    .to_str()
    .unwrap()
    .to_string();

    let string_pass = unsafe {
        assert!(!pass_to_check.is_null());

        CStr::from_ptr(pass_to_check)
    }
    .to_str()
    .unwrap()
    .to_string();

    return CASScrypt::verify_password(string_hash, string_pass);
}

#[test]
fn scrypt_verify_test() {
    let password = "NotThePasswordYouAreLookingFor";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hash = scrypt_hash(password_ptr);
    let hash_ctr = unsafe { CString::from_raw(hash) };
    let hashed_bytes = hash_ctr.as_bytes_with_nul();
    let hashed_ptr = hashed_bytes.as_ptr() as *const i8;
    let is_valid = scrypt_verify(hashed_ptr, password_ptr);
    assert_eq!(true, is_valid);
}