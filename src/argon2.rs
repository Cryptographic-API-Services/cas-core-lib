use core::slice;
use std::{
    env::home_dir,
    ffi::{c_char, c_uchar, CStr, CString},
    num, thread,
};

extern crate rayon;

use std::sync::mpsc::{channel, Receiver};

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rayon::iter::{IntoParallelIterator, IntoParallelRefMutIterator, ParallelIterator};

#[repr(C)]
pub struct Argon2ThreadResult {
    pub passwords: *mut *mut c_char,
    pub length: usize,
}

#[no_mangle]
pub extern "C" fn argon2_verify(hashed_pass: *const c_char, password: *const c_char) -> bool {
    let hashed_pass_string = unsafe {
        assert!(!hashed_pass.is_null());
        CStr::from_ptr(hashed_pass)
    }
    .to_str()
    .unwrap();

    let password_string = unsafe {
        assert!(!password.is_null());
        CStr::from_ptr(password)
    }
    .to_str()
    .unwrap()
    .as_bytes();

    let parsed_hash = PasswordHash::new(&hashed_pass_string).unwrap();
    let result = Argon2::default()
        .verify_password(password_string, &parsed_hash)
        .is_ok();
    return result;
}

#[test]
fn argon2_verify_test() {
    let password = "PasswordToVerify";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password = argon2_hash(password_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password) };
    let hashed_password_bytes = hashed_password_ctr.as_bytes_with_nul();
    let hashed_password_ptr = hashed_password_bytes.as_ptr() as *const i8;
    let is_valid = argon2_verify(hashed_password_ptr, password_ptr);
    assert_eq!(true, is_valid);
}

#[no_mangle]
pub extern "C" fn argon2_verify_thread(
    hashed_pass: *const c_char,
    password: *const c_char,
) -> bool {
    let hashed_pass_string = unsafe {
        assert!(!hashed_pass.is_null());
        CStr::from_ptr(hashed_pass)
    }
    .to_str()
    .unwrap();

    let password_string = unsafe {
        assert!(!password.is_null());
        CStr::from_ptr(password)
    }
    .to_str()
    .unwrap()
    .as_bytes();
    let result = thread::spawn(move || {
        let parsed_hash = PasswordHash::new(&hashed_pass_string).unwrap();
        return Argon2::default()
            .verify_password(password_string, &parsed_hash)
            .is_ok();
    })
    .join()
    .unwrap();
    return result;
}

#[test]
fn argon2_verify_thread_test() {
    let password = "PasswordToVerify";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password = argon2_hash(password_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password) };
    let hashed_password_bytes = hashed_password_ctr.as_bytes_with_nul();
    let hashed_password_ptr = hashed_password_bytes.as_ptr() as *const i8;
    let is_valid = argon2_verify_thread(hashed_password_ptr, password_ptr);
    assert_eq!(true, is_valid);
}

#[no_mangle]
pub extern "C" fn argon2_hash(pass_to_hash: *const c_char) -> *mut c_char {
    let pass_bytes = unsafe {
        assert!(!pass_to_hash.is_null());
        CStr::from_ptr(pass_to_hash)
    }
    .to_str()
    .unwrap()
    .as_bytes();
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = CString::new(argon2.hash_password(pass_bytes, &salt).unwrap().to_string())
        .unwrap()
        .into_raw();
    return password_hash;
}

#[test]
fn argon2_hash_test() {
    let password = "DontUseThisPassword";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password_ptr = argon2_hash(password_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password_ptr) };
    let hashed_password_str = hashed_password_ctr.to_str().unwrap();
    assert_ne!(password, hashed_password_str);
}

#[no_mangle]
pub extern "C" fn argon2_hash_thread(
    passwords_to_hash: *const *const c_char,
    num_of_passwords: usize,
) -> Argon2ThreadResult {
    let mut parsed_passwords_to_hash: Vec<&[u8]> = Vec::new();
    unsafe {
        for i in 0..num_of_passwords {
            let c_str = CStr::from_ptr(*passwords_to_hash.offset(i as isize));
            let str_slice = c_str.to_str().unwrap().as_bytes();
            parsed_passwords_to_hash.push(str_slice);
        }
    }
    let (sender, receiver): (std::sync::mpsc::Sender<String>, Receiver<String>) = channel();
    let argon2 = Argon2::default();
    parsed_passwords_to_hash.par_iter_mut().for_each_with(
        sender.clone(),
        |task_sender, password| {
            let salt = SaltString::generate(&mut OsRng);
            let hashed_password = argon2.hash_password(password, &salt).unwrap().to_string();
            let _ = task_sender.send(hashed_password);
        },
    );
    let mut hashed_passwords: Vec<*mut i8> = Vec::new();
    for _ in 0..parsed_passwords_to_hash.len() {
        let result: String = receiver
            .recv()
            .expect("Error receiving hashed passsword result");
        hashed_passwords.push(CString::new(result).unwrap().into_raw());
    }
    let capacity = hashed_passwords.capacity();
    hashed_passwords.reserve_exact(capacity);
    let result = Argon2ThreadResult {
        passwords: hashed_passwords.as_mut_ptr(),
        length: hashed_passwords.len(),
    };
    std::mem::forget(hashed_passwords);
    return result;
}

#[test]
fn argon2_hash_thread_test() {
    let mut passwords_to_hash = Vec::new();
    passwords_to_hash.push(
        CString::new("welcome")
            .unwrap()
            .as_bytes_with_nul()
            .as_ptr() as *const i8,
    );
    passwords_to_hash.push(
        CString::new("welcome123")
            .unwrap()
            .as_bytes_with_nul()
            .as_ptr() as *const i8,
    );
    let passwords_length = passwords_to_hash.len();
    let result = argon2_hash_thread(passwords_to_hash.as_mut_ptr(), passwords_length);
    let result_slice = unsafe { slice::from_raw_parts(result.passwords, result.length) };
    assert_eq!(result_slice.len(), passwords_to_hash.len());
}
