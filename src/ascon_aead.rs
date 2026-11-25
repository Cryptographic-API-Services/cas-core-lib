use std::ffi::c_uchar;
use cas_lib::sponges::ascon_aead::AsconAead;
use cas_lib::sponges::cas_ascon_aead::{CASAsconAead};

use crate::helpers::{cas_error_code, export_bytes};

#[repr(C)]
pub struct Ascon128EncryptResult {
    ciphertext: *mut c_uchar,
    length: usize,
    error_code: i32,
}

#[repr(C)]
pub struct Ascon128DecryptResult {
    plaintext: *mut c_uchar,
    length: usize,
    error_code: i32,
}

#[repr(C)]
pub struct Ascon128Key {
    key: *mut c_uchar,
    length: usize
}

#[repr(C)]
pub struct Ascon128Nonce {
    nonce: *mut c_uchar,
    length: usize
}

#[no_mangle]
pub extern "C" fn ascon_128_key() -> Ascon128Key {
    let key = <AsconAead as CASAsconAead>::generate_key();
    let result = Ascon128Key {
        key: export_bytes(&key),
        length: key.len()
    };
    result
}



#[no_mangle]
pub extern "C" fn ascon_128_nonce() -> Ascon128Nonce {
    let nonce = <AsconAead as CASAsconAead>::generate_nonce();
    let result = Ascon128Nonce {
        nonce: export_bytes(&nonce),
        length: nonce.len()
    };
    result
}


#[no_mangle]
pub extern "C" fn ascon_128_encrypt(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
) -> Ascon128EncryptResult {
    let nonce_key = unsafe { std::slice::from_raw_parts(nonce_key, nonce_key_length) }.to_vec();
    let key = unsafe { std::slice::from_raw_parts(key, key_length) }.to_vec();
    let to_encrypt = unsafe { std::slice::from_raw_parts(to_encrypt, to_encrypt_length) }.to_vec();
    match <AsconAead as CASAsconAead>::encrypt(key, nonce_key, to_encrypt) {
        Ok(ciphertext) => {
            let result = Ascon128EncryptResult {
                ciphertext: export_bytes(&ciphertext),
                length: ciphertext.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => Ascon128EncryptResult {
            ciphertext: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}




#[no_mangle]
pub extern "C" fn ascon_128_decrypt(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
) -> Ascon128DecryptResult {
    let nonce_key = unsafe { std::slice::from_raw_parts(nonce_key, nonce_key_length) }.to_vec();
    let key = unsafe { std::slice::from_raw_parts(key, key_length) }.to_vec();
    let to_decrypt = unsafe { std::slice::from_raw_parts(to_decrypt, to_decrypt_length) }.to_vec();
    match <AsconAead as CASAsconAead>::decrypt(key, nonce_key, to_decrypt) {
        Ok(plaintext) => {
            let result = Ascon128DecryptResult {
                plaintext: export_bytes(&plaintext),
                length: plaintext.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => Ascon128DecryptResult {
            plaintext: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}