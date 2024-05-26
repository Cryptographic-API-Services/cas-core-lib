use std::ffi::{c_char, c_uchar, CStr, CString};
use cas_lib::sponges::ascon_aead::AsconAead;
use cas_lib::sponges::cas_ascon_aead::{CASAsconAead};

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
    let mut key = <AsconAead as CASAsconAead>::generate_key();
    let capacity = key.capacity();
    key.reserve_exact(capacity);
    let result = Ascon128Key {
        key: key.as_mut_ptr(),
        length: key.len()
    };
    std::mem::forget(key);
    result
}

#[no_mangle]
pub extern "C" fn ascon_128_key_threadpool() -> Ascon128Key {
    let mut key = <AsconAead as CASAsconAead>::generate_key_threadpool();
    let capacity = key.capacity();
    key.reserve_exact(capacity);
    let result = Ascon128Key {
        key: key.as_mut_ptr(),
        length: key.len()
    };
    std::mem::forget(key);
    result
}



#[no_mangle]
pub extern "C" fn ascon_128_nonce() -> Ascon128Nonce {
    let mut nonce = <AsconAead as CASAsconAead>::generate_nonce();
    let capacity = nonce.capacity();
    nonce.reserve_exact(capacity);
    let result = Ascon128Nonce {
        nonce: nonce.as_mut_ptr(),
        length: nonce.len()
    };
    std::mem::forget(nonce);
    result
}

#[no_mangle]
pub extern "C" fn ascon_128_nonce_threadpool() -> Ascon128Nonce {
    let mut nonce = <AsconAead as CASAsconAead>::generate_nonce_threadpool();
    let capacity = nonce.capacity();
    nonce.reserve_exact(capacity);
    let result = Ascon128Nonce {
        nonce: nonce.as_mut_ptr(),
        length: nonce.len()
    };
    std::mem::forget(nonce);
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
    let mut ciphertext = <AsconAead as CASAsconAead>::encrypt(key, nonce_key, to_encrypt);
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
pub extern "C" fn ascon_128_encrypt_threadpool(
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
    let mut ciphertext = <AsconAead as CASAsconAead>::encrypt_threadpool(key, nonce_key, to_encrypt);
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
    let mut plaintext = <AsconAead as CASAsconAead>::decrypt(key, nonce_key, to_decrypt);
    let capacity = plaintext.capacity();
    plaintext.reserve_exact(capacity);
    let result = Ascon128DecryptResult {
        plaintext: plaintext.as_mut_ptr(),
        length: plaintext.len(),
    };
    std::mem::forget(plaintext);
    result
}

#[no_mangle]
pub extern "C" fn ascon_128_decrypt_threadpool(
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
    let mut plaintext = <AsconAead as CASAsconAead>::decrypt_threadpool(key, nonce_key, to_decrypt);
    let capacity = plaintext.capacity();
    plaintext.reserve_exact(capacity);
    let result = Ascon128DecryptResult {
        plaintext: plaintext.as_mut_ptr(),
        length: plaintext.len(),
    };
    std::mem::forget(plaintext);
    result
}