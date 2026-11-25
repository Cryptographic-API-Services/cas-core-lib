use std::ffi::c_uchar;

use cas_lib::hybrid::{cas_hybrid::CASHybrid, hpke::CASHPKE};
use types::{HpkeDecrypt, HpkeEncrypt, HpkeKeyPair};

use crate::helpers::{cas_error_code, export_bytes};

mod types;

#[no_mangle]
pub extern "C" fn hpke_generate_keypair() -> HpkeKeyPair {
    let (private_key, public_key, info_str) = <CASHPKE as CASHybrid>::generate_key_pair();
    let return_result = HpkeKeyPair {
        private_key_ptr: export_bytes(&private_key),
        private_key_ptr_length: private_key.len(),
        public_key_ptr: export_bytes(&public_key),
        public_key_ptr_length: public_key.len(),
        info_str_ptr: export_bytes(&info_str),
        info_str_ptr_length: info_str.len()
    };
    return_result
}

#[no_mangle]
pub extern "C" fn hpke_encrypt(
    plaintext: *const c_uchar,
    plaintext_length: usize,
    public_key: *const c_uchar,
    public_keylength: usize,
    info_str: *const c_uchar,
    info_str_length: usize,
) -> HpkeEncrypt {
    let plaintext = unsafe { std::slice::from_raw_parts(plaintext, plaintext_length) }.to_vec();
    let public_key = unsafe { std::slice::from_raw_parts(public_key, public_keylength) }.to_vec();
    let info_str = unsafe { std::slice::from_raw_parts(info_str, info_str_length) }.to_vec();
    match <CASHPKE as CASHybrid>::encrypt(plaintext, public_key, info_str) {
        Ok((encapped_key, ciphertext, tag)) => {
            let return_result = HpkeEncrypt {
                encapped_key_ptr: export_bytes(&encapped_key),
                encapped_key_ptr_length: encapped_key.len(),
                ciphertext_ptr: export_bytes(&ciphertext),
                ciphertext_ptr_length: ciphertext.len(),
                tag_ptr: export_bytes(&tag),
                tag_ptr_length: tag.len(),
                error_code: 0,
            };
            return_result
        }
        Err(e) => HpkeEncrypt {
            encapped_key_ptr: std::ptr::null_mut(),
            encapped_key_ptr_length: 0,
            ciphertext_ptr: std::ptr::null_mut(),
            ciphertext_ptr_length: 0,
            tag_ptr: std::ptr::null_mut(),
            tag_ptr_length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

#[no_mangle]
pub extern "C" fn hpke_decrypt(
    ciphertext: *const c_uchar,
    ciphertext_length: usize,
    private_key: *const c_uchar,
    private_keylength: usize,
    encapped_key: *const c_uchar,
    encapped_key_length: usize,
    tag: *const c_uchar,
    tag_length: usize,
    info_str: *const c_uchar,
    info_str_length: usize,
) -> HpkeDecrypt {
    let ciphertext = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_length) }.to_vec();
    let private_key = unsafe { std::slice::from_raw_parts(private_key, private_keylength) }.to_vec();
    let encapped_key = unsafe { std::slice::from_raw_parts(encapped_key, encapped_key_length) }.to_vec();
    let tag = unsafe { std::slice::from_raw_parts(tag, tag_length)}.to_vec();
    let info_str = unsafe { std::slice::from_raw_parts(info_str, info_str_length) }.to_vec();
    match <CASHPKE as CASHybrid>::decrypt(ciphertext, private_key, encapped_key, tag, info_str) {
        Ok(plaintext) => {
            let return_result = HpkeDecrypt {
                plaintext_ptr: export_bytes(&plaintext),
                plaintext_ptr_length: plaintext.len(),
                error_code: 0,
            };
            return_result
        }
        Err(e) => HpkeDecrypt {
            plaintext_ptr: std::ptr::null_mut(),
            plaintext_ptr_length: 0,
            error_code: cas_error_code(&e),
        },
    }
}