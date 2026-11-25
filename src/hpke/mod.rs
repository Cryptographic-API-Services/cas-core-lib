use std::ffi::c_uchar;

use cas_lib::hybrid::{cas_hybrid::CASHybrid, hpke::CASHPKE};
use types::{HpkeDecrypt, HpkeEncrypt, HpkeKeyPair};

#[cfg(test)]
use cas_lib::error::CasError;

use crate::helpers::{bytes_from_ffi, cas_error_code, export_bytes};

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
    aad: *const c_uchar,
    aad_length: usize,
) -> HpkeEncrypt {
    let plaintext = unsafe { std::slice::from_raw_parts(plaintext, plaintext_length) }.to_vec();
    let public_key = unsafe { std::slice::from_raw_parts(public_key, public_keylength) }.to_vec();
    let info_str = unsafe { std::slice::from_raw_parts(info_str, info_str_length) }.to_vec();
    let result = bytes_from_ffi(aad, aad_length)
        .and_then(|aad| <CASHPKE as CASHybrid>::encrypt(plaintext, public_key, info_str, aad));
    match result {
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
    aad: *const c_uchar,
    aad_length: usize,
) -> HpkeDecrypt {
    let ciphertext = unsafe { std::slice::from_raw_parts(ciphertext, ciphertext_length) }.to_vec();
    let private_key = unsafe { std::slice::from_raw_parts(private_key, private_keylength) }.to_vec();
    let encapped_key = unsafe { std::slice::from_raw_parts(encapped_key, encapped_key_length) }.to_vec();
    let tag = unsafe { std::slice::from_raw_parts(tag, tag_length)}.to_vec();
    let info_str = unsafe { std::slice::from_raw_parts(info_str, info_str_length) }.to_vec();
    let result = bytes_from_ffi(aad, aad_length)
        .and_then(|aad| <CASHPKE as CASHybrid>::decrypt(ciphertext, private_key, encapped_key, tag, info_str, aad));
    match result {
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

// Copies a returned buffer. The original is leaked, like the other inline tests do.
#[cfg(test)]
fn take_bytes(ptr: *mut c_uchar, length: usize) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts(ptr, length) }.to_vec()
}

#[cfg(test)]
fn hpke_round_trip(encrypt_aad: &[u8], decrypt_aad: &[u8]) -> (HpkeDecrypt, Vec<u8>) {
    let key_pair = hpke_generate_keypair();
    let private_key = take_bytes(key_pair.private_key_ptr, key_pair.private_key_ptr_length);
    let public_key = take_bytes(key_pair.public_key_ptr, key_pair.public_key_ptr_length);
    let info_str = take_bytes(key_pair.info_str_ptr, key_pair.info_str_ptr_length);
    let plaintext = b"HPKE message to encrypt".to_vec();
    let encrypted = hpke_encrypt(
        plaintext.as_ptr(),
        plaintext.len(),
        public_key.as_ptr(),
        public_key.len(),
        info_str.as_ptr(),
        info_str.len(),
        encrypt_aad.as_ptr(),
        encrypt_aad.len(),
    );
    assert_eq!(0, encrypted.error_code);
    let encapped_key = take_bytes(encrypted.encapped_key_ptr, encrypted.encapped_key_ptr_length);
    let ciphertext = take_bytes(encrypted.ciphertext_ptr, encrypted.ciphertext_ptr_length);
    let tag = take_bytes(encrypted.tag_ptr, encrypted.tag_ptr_length);
    let decrypted = hpke_decrypt(
        ciphertext.as_ptr(),
        ciphertext.len(),
        private_key.as_ptr(),
        private_key.len(),
        encapped_key.as_ptr(),
        encapped_key.len(),
        tag.as_ptr(),
        tag.len(),
        info_str.as_ptr(),
        info_str.len(),
        decrypt_aad.as_ptr(),
        decrypt_aad.len(),
    );
    (decrypted, plaintext)
}

#[test]
fn hpke_encrypt_decrypt_without_aad_test() {
    let (decrypted, plaintext) = hpke_round_trip(&[], &[]);
    assert_eq!(0, decrypted.error_code);
    assert_eq!(plaintext, take_bytes(decrypted.plaintext_ptr, decrypted.plaintext_ptr_length));
}

#[test]
fn hpke_encrypt_decrypt_with_aad_test() {
    let (decrypted, plaintext) = hpke_round_trip(b"header", b"header");
    assert_eq!(0, decrypted.error_code);
    assert_eq!(plaintext, take_bytes(decrypted.plaintext_ptr, decrypted.plaintext_ptr_length));
}

#[test]
fn hpke_decrypt_wrong_aad_fails_test() {
    let (decrypted, _) = hpke_round_trip(b"header", b"other header");
    assert!(decrypted.plaintext_ptr.is_null());
    assert_eq!(cas_error_code(&CasError::DecryptionFailed), decrypted.error_code);
}

#[test]
fn hpke_decrypt_missing_aad_fails_test() {
    let (decrypted, _) = hpke_round_trip(b"header", &[]);
    assert!(decrypted.plaintext_ptr.is_null());
    assert_eq!(cas_error_code(&CasError::DecryptionFailed), decrypted.error_code);
}

#[test]
fn hpke_encrypt_null_aad_with_length_is_invalid_input_test() {
    let key_pair = hpke_generate_keypair();
    let public_key = take_bytes(key_pair.public_key_ptr, key_pair.public_key_ptr_length);
    let info_str = take_bytes(key_pair.info_str_ptr, key_pair.info_str_ptr_length);
    let plaintext = b"HPKE message".to_vec();
    let encrypted = hpke_encrypt(
        plaintext.as_ptr(),
        plaintext.len(),
        public_key.as_ptr(),
        public_key.len(),
        info_str.as_ptr(),
        info_str.len(),
        std::ptr::null(),
        4,
    );
    assert!(encrypted.ciphertext_ptr.is_null());
    assert_eq!(cas_error_code(&CasError::InvalidInput), encrypted.error_code);
}
