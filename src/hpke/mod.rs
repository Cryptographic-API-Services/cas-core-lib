use std::ffi::c_uchar;

use cas_lib::hybrid::{cas_hybrid::CASHybrid, hpke::CASHPKE};
use types::{HpkeDecrypt, HpkeEncrypt, HpkeKeyPair};

mod types;

#[no_mangle]
pub extern "C" fn hpke_generate_keypair() -> HpkeKeyPair {
    let (mut private_key, mut public_key, mut info_str) = <CASHPKE as CASHybrid>::generate_key_pair();
    let private_key_capacity = private_key.capacity();
    private_key.reserve_exact(private_key_capacity);
    let public_key_capacity = public_key.capacity();
    public_key.reserve_exact(public_key_capacity);
    let info_str_capacity = info_str.capacity();
    info_str.reserve_exact(info_str_capacity);
    let return_result = HpkeKeyPair {
        private_key_ptr: private_key.as_mut_ptr(),
        private_key_ptr_length: private_key.len(),
        public_key_ptr: public_key.as_mut_ptr(),
        public_key_ptr_length: public_key.len(),
        info_str_ptr: info_str.as_mut_ptr(),
        info_str_ptr_length: info_str.len()
    };
    std::mem::forget(private_key);
    std::mem::forget(public_key);
    std::mem::forget(info_str);
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
    let (mut encapped_key, mut ciphertext, mut tag) = <CASHPKE as CASHybrid>::encrypt(plaintext, public_key, info_str);
    let encapped_key_capacity = encapped_key.capacity();
    encapped_key.reserve_exact(encapped_key_capacity);
    let ciphertext_capacity = ciphertext.capacity();
    ciphertext.reserve_exact(ciphertext_capacity);
    let tag_capacity = tag.capacity();
    tag.reserve_exact(tag_capacity);
    let return_result = HpkeEncrypt {
        encapped_key_ptr: encapped_key.as_mut_ptr(),
        encapped_key_ptr_length: encapped_key.len(),
        ciphertext_ptr: ciphertext.as_mut_ptr(),
        ciphertext_ptr_length: ciphertext.len(),
        tag_ptr: tag.as_mut_ptr(),
        tag_ptr_length: tag.len()
    };
    std::mem::forget(encapped_key);
    std::mem::forget(ciphertext);
    std::mem::forget(tag);
    return_result
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
    let mut plaintext = <CASHPKE as CASHybrid>::decrypt(ciphertext, private_key, encapped_key, tag, info_str);
    let plaintext_capacity = plaintext.capacity();
    plaintext.reserve_exact(plaintext_capacity);
    let return_result = HpkeDecrypt {
        plaintext_ptr: plaintext.as_mut_ptr(),
        plaintext_ptr_length: plaintext.len()
    };
    std::mem::forget(plaintext);
    return_result
}