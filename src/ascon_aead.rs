use std::ffi::{c_char, c_uchar, CStr, CString};

use ascon_aead::aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng};
use ascon_aead::Ascon128;

#[repr(C)]
pub struct Ascon128EncryptResult {
    ciphertext: *mut c_uchar,
    length: usize,
}

#[repr(C)]
pub struct Ascon128DecryptResult {
    plaintext: *mut c_uchar,
    length: usize,
}

#[no_mangle]
pub extern "C" fn ascon_128_key() -> *mut c_char {
    return CString::new(base64::encode(Ascon128::generate_key(&mut OsRng)))
        .unwrap()
        .into_raw();
}

#[no_mangle]
pub extern "C" fn ascon_128_nonce() -> *mut c_char {
    return CString::new(base64::encode(Ascon128::generate_nonce(&mut OsRng)))
        .unwrap()
        .into_raw();
}

#[no_mangle]
pub extern "C" fn ascon_128_encrypt(
    nonce_key: *const c_char,
    key: *const c_char,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
) -> Ascon128EncryptResult {
    let nonce_key = unsafe { CStr::from_ptr(nonce_key) }.to_str().unwrap();
    let key = unsafe { CStr::from_ptr(key) }.to_str().unwrap();
    let to_encrypt = unsafe { std::slice::from_raw_parts(to_encrypt, to_encrypt_length) };

    let decoded_nonce_key = base64::decode(nonce_key).unwrap();
    let decoded_key = base64::decode(key).unwrap();

    let key = GenericArray::from_slice(&decoded_nonce_key);
    let nonce_key = GenericArray::from_slice(&decoded_key);

    let cipher = Ascon128::new(key);
    let mut ciphertext = cipher.encrypt(&nonce_key, to_encrypt.as_ref()).unwrap();
    let capacity = ciphertext.capacity();
    ciphertext.reserve_exact(capacity);
    let result = Ascon128EncryptResult {
        ciphertext: ciphertext.as_mut_ptr(),
        length: ciphertext.len(),
    };
    std::mem::forget(ciphertext);
    result
}


#[no_mangle]
pub extern "C" fn ascon_128_decrypt(
    nonce_key: *const c_char,
    key: *const c_char,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
) -> Ascon128DecryptResult {
    let nonce_key = unsafe { CStr::from_ptr(nonce_key) }.to_str().unwrap();
    let key = unsafe { CStr::from_ptr(key) }.to_str().unwrap();
    let to_encrypt = unsafe { std::slice::from_raw_parts(to_encrypt, to_encrypt_length) };

    let decoded_nonce_key = base64::decode(nonce_key).unwrap();
    let decoded_key = base64::decode(key).unwrap();

    let key = GenericArray::from_slice(&decoded_nonce_key);
    let nonce_key = GenericArray::from_slice(&decoded_key);

    let cipher = Ascon128::new(key);
    let mut plaintext = cipher.decrypt(&nonce_key, to_encrypt.as_ref()).unwrap();
    let capacity = plaintext.capacity();
    plaintext.reserve_exact(capacity);
    let result = Ascon128DecryptResult {
        plaintext: plaintext.as_mut_ptr(),
        length: plaintext.len(),
    };
    std::mem::forget(plaintext);
    result
}