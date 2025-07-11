use cas_lib::symmetric::{aes::{CASAES128, CASAES256}, cas_symmetric_encryption::{CASAES128Encryption, CASAES256Encryption}};
use std::ffi::c_uchar;

use crate::x25519;

#[repr(C)]
pub struct AesNonce {
    pub nonce: *mut c_uchar,
    pub length: usize
}

#[repr(C)]
pub struct AesKeyResult {
    pub key: *mut c_uchar,
    pub length: usize
}

#[repr(C)]
pub struct AesBytesEncrypt {
    pub ciphertext: *mut c_uchar,
    pub length: usize,
}

#[repr(C)]
pub struct AesBytesDecrypt {
    pub plaintext: *mut c_uchar,
    pub length: usize,
}

#[repr(C)]
pub struct AesNonceAndKeyFromX25519DiffieHellman {
    pub aes_key_ptr: *mut c_uchar,
    pub aes_key_ptr_length: usize,
    pub aes_nonce_ptr: *mut c_uchar,
    pub aes_nonce_ptr_length: usize
}

#[no_mangle]
pub extern "C" fn aes_256_key_and_nonce_from_x25519_diffie_hellman_shared_secret(
    shared_secret: *const c_uchar,
    shared_secret_length: usize,
) -> AesNonceAndKeyFromX25519DiffieHellman {
    let shared_secret_slice: Vec<u8> =
        unsafe { std::slice::from_raw_parts(shared_secret, shared_secret_length) }.to_vec();

        let mut aes_nonce = Vec::with_capacity(12);
        aes_nonce.resize(12, 0);
        aes_nonce.copy_from_slice(&shared_secret_slice[..12]);
        let capacity = aes_nonce.capacity();
        aes_nonce.reserve_exact(capacity);
        
        let mut aes_key = <CASAES256 as CASAES256Encryption>::key_from_vec(shared_secret_slice);
        let aes_key_capacity = aes_key.capacity();
        aes_key.reserve_exact(aes_key_capacity);

    let result = AesNonceAndKeyFromX25519DiffieHellman {
        aes_key_ptr: aes_key.as_mut_ptr(),
        aes_key_ptr_length: aes_key.len(),
        aes_nonce_ptr: aes_nonce.as_mut_ptr(),
        aes_nonce_ptr_length: aes_nonce.len()
    };
    std::mem::forget(aes_nonce);
    std::mem::forget(aes_key);
    result
}

#[no_mangle]
pub extern "C" fn aes_256_key_and_nonce_from_x25519_diffie_hellman_shared_secret_threadpool(
    shared_secret: *const c_uchar,
    shared_secret_length: usize,
) -> AesNonceAndKeyFromX25519DiffieHellman {
    let shared_secret_slice: Vec<u8> =
        unsafe { std::slice::from_raw_parts(shared_secret, shared_secret_length) }.to_vec();

        let mut aes_nonce = Vec::with_capacity(12);
        aes_nonce.resize(12, 0);
        aes_nonce.copy_from_slice(&shared_secret_slice[..12]);
        let capacity = aes_nonce.capacity();
        aes_nonce.reserve_exact(capacity);
        
        let mut aes_key = <CASAES256 as CASAES256Encryption>::key_from_vec_threadpool(shared_secret_slice);
        let aes_key_capacity = aes_key.capacity();
        aes_key.reserve_exact(aes_key_capacity);

    let result = AesNonceAndKeyFromX25519DiffieHellman {
        aes_key_ptr: aes_key.as_mut_ptr(),
        aes_key_ptr_length: aes_key.len(),
        aes_nonce_ptr: aes_nonce.as_mut_ptr(),
        aes_nonce_ptr_length: aes_nonce.len()
    };
    std::mem::forget(aes_nonce);
    std::mem::forget(aes_key);
    result
}

#[test]
pub fn aes_256_key_and_nonce_from_x25519_diffie_hellman_shared_secret_test() {
    let alice_secret_and_public_key = x25519::generate_secret_and_public_key();
    let bob_secret_and_public_key = x25519::generate_secret_and_public_key();
    let alice_shared_secret = x25519::diffie_hellman(
        alice_secret_and_public_key.secret_key,
        alice_secret_and_public_key.secret_key_length,
        bob_secret_and_public_key.public_key,
        bob_secret_and_public_key.public_key_length,
    );
    let bob_shared_secret = x25519::diffie_hellman(
        bob_secret_and_public_key.secret_key,
        bob_secret_and_public_key.secret_key_length,
        alice_secret_and_public_key.public_key,
        alice_secret_and_public_key.public_key_length,
    );
    let alice_shared_secret_slice: &[u8] = unsafe {
        std::slice::from_raw_parts(
            alice_shared_secret.shared_secret,
            alice_shared_secret.shared_secret_length,
        )
    };
    let bob_shared_secret_slice: &[u8] = unsafe {
        std::slice::from_raw_parts(
            bob_shared_secret.shared_secret,
            bob_shared_secret.shared_secret_length,
        )
    };
    assert_eq!(alice_shared_secret_slice, bob_shared_secret_slice);

    let alice_secret_key: *const std::os::raw::c_uchar = alice_shared_secret.shared_secret;

    let alice_aes = aes_256_key_and_nonce_from_x25519_diffie_hellman_shared_secret(
        alice_secret_key,
        alice_shared_secret.shared_secret_length,
    );
    
    let bob_aes = aes_256_key_and_nonce_from_x25519_diffie_hellman_shared_secret(
        bob_shared_secret.shared_secret,
        bob_shared_secret.shared_secret_length,
    );

    let password = "DontUseThisPassword";
    let password_cstr = password.as_bytes();
    let password_ptr = password.as_ptr();
    let cipher_text_result = aes_256_encrypt_bytes_with_key(alice_aes.aes_nonce_ptr, alice_aes.aes_nonce_ptr_length, alice_aes.aes_key_ptr, alice_aes.aes_key_ptr_length, password_ptr, password_cstr.len());
    let plain_text_result = aes_256_decrypt_bytes_with_key(bob_aes.aes_nonce_ptr, bob_aes.aes_nonce_ptr_length, bob_aes.aes_key_ptr, bob_aes.aes_key_ptr_length, cipher_text_result.ciphertext, cipher_text_result.length);
    let plain_text_result_slice: &[u8] = unsafe {
         std::slice::from_raw_parts(
             plain_text_result.plaintext,
             plain_text_result.length,
         )
     };
     assert_eq!(password_cstr, plain_text_result_slice);
}

#[no_mangle]
pub extern "C" fn aes_128_key_and_nonce_from_x25519_diffie_hellman_shared_secret(
    shared_secret: *const c_uchar,
    shared_secret_length: usize,
) -> AesNonceAndKeyFromX25519DiffieHellman {
    let shared_secret_slice: Vec<u8> =
        unsafe { std::slice::from_raw_parts(shared_secret, shared_secret_length) }.to_vec();

    let mut shorted_shared_secret: [u8; 16] = Default::default();
    shorted_shared_secret.copy_from_slice(&shared_secret_slice[..16]);
    let mut aes_nonce = Vec::with_capacity(12);
    aes_nonce.resize(12, 0);
    aes_nonce.copy_from_slice(&shared_secret_slice[..12]);
    let capacity = aes_nonce.capacity();
    aes_nonce.reserve_exact(capacity);

    let mut aes_key = <CASAES128 as CASAES128Encryption>::key_from_vec(shorted_shared_secret.to_vec());
    let aes_key_capacity = aes_key.capacity();
    aes_key.reserve_exact(aes_key_capacity);

    let result = AesNonceAndKeyFromX25519DiffieHellman {
        aes_key_ptr: aes_key.as_mut_ptr(),
        aes_key_ptr_length: aes_key.len(),
        aes_nonce_ptr: aes_nonce.as_mut_ptr(),
        aes_nonce_ptr_length: aes_nonce.len()
    };
    std::mem::forget(aes_nonce);
    std::mem::forget(aes_key);
    result
}

#[no_mangle]
pub extern "C" fn aes_128_key_and_nonce_from_x25519_diffie_hellman_shared_secret_threadpool(
    shared_secret: *const c_uchar,
    shared_secret_length: usize,
) -> AesNonceAndKeyFromX25519DiffieHellman {
    let shared_secret_slice: Vec<u8> =
        unsafe { std::slice::from_raw_parts(shared_secret, shared_secret_length) }.to_vec();

    let mut shorted_shared_secret: [u8; 16] = Default::default();
    shorted_shared_secret.copy_from_slice(&shared_secret_slice[..16]);
    let mut aes_nonce = Vec::with_capacity(12);
    aes_nonce.resize(12, 0);
    aes_nonce.copy_from_slice(&shared_secret_slice[..12]);
    let capacity = aes_nonce.capacity();
    aes_nonce.reserve_exact(capacity);

    let mut aes_key = <CASAES128 as CASAES128Encryption>::key_from_vec_threadpool(shorted_shared_secret.to_vec());
    let aes_key_capacity = aes_key.capacity();
    aes_key.reserve_exact(aes_key_capacity);

    let result = AesNonceAndKeyFromX25519DiffieHellman {
        aes_key_ptr: aes_key.as_mut_ptr(),
        aes_key_ptr_length: aes_key.len(),
        aes_nonce_ptr: aes_nonce.as_mut_ptr(),
        aes_nonce_ptr_length: aes_nonce.len()
    };
    std::mem::forget(aes_nonce);
    std::mem::forget(aes_key);
    result
}

#[test]
pub fn aes_128_key_and_nonce_from_x25519_diffie_hellman_shared_secret_test() {
    let alice_secret_and_public_key = x25519::generate_secret_and_public_key();
    let bob_secret_and_public_key = x25519::generate_secret_and_public_key();
    let alice_shared_secret = x25519::diffie_hellman(
        alice_secret_and_public_key.secret_key,
        alice_secret_and_public_key.secret_key_length,
        bob_secret_and_public_key.public_key,
        bob_secret_and_public_key.public_key_length,
    );
    let bob_shared_secret = x25519::diffie_hellman(
        bob_secret_and_public_key.secret_key,
        bob_secret_and_public_key.secret_key_length,
        alice_secret_and_public_key.public_key,
        alice_secret_and_public_key.public_key_length,
    );
    let alice_shared_secret_slice: &[u8] = unsafe {
        std::slice::from_raw_parts(
            alice_shared_secret.shared_secret,
            alice_shared_secret.shared_secret_length,
        )
    };
    let bob_shared_secret_slice: &[u8] = unsafe {
        std::slice::from_raw_parts(
            bob_shared_secret.shared_secret,
            bob_shared_secret.shared_secret_length,
        )
    };
    assert_eq!(alice_shared_secret_slice, bob_shared_secret_slice);

    let alice_secret_key: *const std::os::raw::c_uchar = alice_shared_secret.shared_secret;

    let alice_aes = aes_128_key_and_nonce_from_x25519_diffie_hellman_shared_secret(
        alice_secret_key,
        alice_shared_secret.shared_secret_length,
    );
    
    let bob_aes = aes_128_key_and_nonce_from_x25519_diffie_hellman_shared_secret(
        bob_shared_secret.shared_secret,
        bob_shared_secret.shared_secret_length,
    );

    let password = "DontUseThisPassword";
    let password_cstr = password.as_bytes();
    let password_ptr = password.as_ptr();
    let cipher_text_result = aes_128_encrypt_bytes_with_key(alice_aes.aes_nonce_ptr, alice_aes.aes_nonce_ptr_length, alice_aes.aes_key_ptr, alice_aes.aes_key_ptr_length, password_ptr, password_cstr.len());
    let plain_text_result = aes_128_decrypt_bytes_with_key(bob_aes.aes_nonce_ptr, bob_aes.aes_nonce_ptr_length, bob_aes.aes_key_ptr, bob_aes.aes_key_ptr_length, cipher_text_result.ciphertext, cipher_text_result.length);
    let plain_text_result_slice: &[u8] = unsafe {
        std::slice::from_raw_parts(
            plain_text_result.plaintext,
            plain_text_result.length,
        )
    };
    assert_eq!(password_cstr, plain_text_result_slice);
}

#[no_mangle]
pub extern "C" fn aes_nonce() -> AesNonce {
    let mut random_bytes = <CASAES256 as CASAES256Encryption>::generate_nonce();
    let capacity = random_bytes.capacity();
    random_bytes.reserve_exact(capacity);
    let result = AesNonce {
        nonce: random_bytes.as_mut_ptr(),
        length: random_bytes.len()
    };
    std::mem::forget(random_bytes);
    result
}

#[no_mangle]
pub extern "C" fn aes_nonce_threadpool() -> AesNonce {
    let mut random_bytes = <CASAES256 as CASAES256Encryption>::generate_nonce_threadpool();
    let capacity = random_bytes.capacity();
    random_bytes.reserve_exact(capacity);
    let result = AesNonce {
        nonce: random_bytes.as_mut_ptr(),
        length: random_bytes.len()
    };
    std::mem::forget(random_bytes);
    result
}

#[no_mangle]
pub extern "C" fn aes_256_key() -> AesKeyResult {
    let mut key = <CASAES256 as CASAES256Encryption>::generate_key();
    let capacity = key.capacity();
    key.reserve_exact(capacity);
    let result = AesKeyResult {
        key: key.as_mut_ptr(),
        length: key.len()
    };
    std::mem::forget(key);
    result
}

#[no_mangle]
pub extern "C" fn aes_256_key_threadpool() -> AesKeyResult {
    let mut key = <CASAES256 as CASAES256Encryption>::generate_key_threadpool();
    let capacity = key.capacity();
    key.reserve_exact(capacity);
    let result = AesKeyResult {
        key: key.as_mut_ptr(),
        length: key.len()
    };
    std::mem::forget(key);
    result
}

#[no_mangle]
pub extern "C" fn aes_128_key() -> AesKeyResult {
    let mut key = <CASAES128 as CASAES128Encryption>::generate_key();
    let capacity = key.capacity();
    key.reserve_exact(capacity);
    let result = AesKeyResult {
        key: key.as_mut_ptr(),
        length: key.len()
    };
    std::mem::forget(key);
    result
}

#[no_mangle]
pub extern "C" fn aes_128_key_threadpool() -> AesKeyResult {
    let mut key = <CASAES128 as CASAES128Encryption>::generate_key_threadpool();
    let capacity = key.capacity();
    key.reserve_exact(capacity);
    let result = AesKeyResult {
        key: key.as_mut_ptr(),
        length: key.len()
    };
    std::mem::forget(key);
    result
}


#[no_mangle]
pub extern "C" fn aes_128_encrypt_bytes_with_key(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
) -> AesBytesEncrypt {
    let nonce_slice: Vec<u8> = unsafe { std::slice::from_raw_parts(nonce_key, nonce_key_length) }.to_vec();
    let key_slice: Vec<u8> = unsafe {std::slice::from_raw_parts(key, key_length)}.to_vec();
    let to_encrypt_slice: Vec<u8> =
        unsafe { std::slice::from_raw_parts(to_encrypt, to_encrypt_length) }.to_vec();
    let mut ciphertext = <CASAES128 as CASAES128Encryption>::encrypt_plaintext(key_slice, nonce_slice, to_encrypt_slice);
    let capacity = ciphertext.capacity();
    ciphertext.reserve_exact(capacity);
    let result = AesBytesEncrypt {
        ciphertext: ciphertext.as_mut_ptr(),
        length: ciphertext.len(),
    };
    std::mem::forget(ciphertext);
    return result;
}

#[no_mangle]
pub extern "C" fn aes_128_encrypt_bytes_with_key_threadpool(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
) -> AesBytesEncrypt {
    let nonce_slice: Vec<u8> = unsafe { std::slice::from_raw_parts(nonce_key, nonce_key_length) }.to_vec();
    let key_slice: Vec<u8> = unsafe {std::slice::from_raw_parts(key, key_length)}.to_vec();
    let to_encrypt_slice: Vec<u8> =
        unsafe { std::slice::from_raw_parts(to_encrypt, to_encrypt_length) }.to_vec();
    let mut ciphertext = <CASAES128 as CASAES128Encryption>::encrypt_plaintext_threadpool(key_slice, nonce_slice, to_encrypt_slice);
    let capacity = ciphertext.capacity();
    ciphertext.reserve_exact(capacity);
    let result = AesBytesEncrypt {
        ciphertext: ciphertext.as_mut_ptr(),
        length: ciphertext.len(),
    };
    std::mem::forget(ciphertext);
    return result;
}

#[no_mangle]
pub extern "C" fn aes_256_encrypt_bytes_with_key(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
) -> AesBytesEncrypt {
    let nonce_slice = unsafe { std::slice::from_raw_parts(nonce_key, nonce_key_length) }.to_vec();
    let key_slice = unsafe {std::slice::from_raw_parts(key, key_length)}.to_vec();
    let to_encrypt_slice = unsafe { std::slice::from_raw_parts(to_encrypt, to_encrypt_length) }.to_vec();
    let mut ciphertext = <CASAES256 as CASAES256Encryption>::encrypt_plaintext(key_slice, nonce_slice, to_encrypt_slice);
    let capacity = ciphertext.capacity();
    ciphertext.reserve_exact(capacity);
    let result = AesBytesEncrypt {
        ciphertext: ciphertext.as_mut_ptr(),
        length: ciphertext.len(),
    };
    std::mem::forget(ciphertext);
    return result;
}

#[no_mangle]
pub extern "C" fn aes_256_encrypt_bytes_with_key_threadpool(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
) -> AesBytesEncrypt {
    let nonce_slice = unsafe { std::slice::from_raw_parts(nonce_key, nonce_key_length) }.to_vec();
    let key_slice = unsafe {std::slice::from_raw_parts(key, key_length)}.to_vec();
    let to_encrypt_slice = unsafe { std::slice::from_raw_parts(to_encrypt, to_encrypt_length) }.to_vec();
    let mut ciphertext = <CASAES256 as CASAES256Encryption>::encrypt_plaintext_threadpool(key_slice, nonce_slice, to_encrypt_slice);
    let capacity = ciphertext.capacity();
    ciphertext.reserve_exact(capacity);
    let result = AesBytesEncrypt {
        ciphertext: ciphertext.as_mut_ptr(),
        length: ciphertext.len(),
    };
    std::mem::forget(ciphertext);
    return result;
}

#[no_mangle]
pub extern "C" fn aes_128_decrypt_bytes_with_key(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
) -> AesBytesDecrypt {
    let nonce_slice = unsafe { std::slice::from_raw_parts(nonce_key, nonce_key_length) }.to_vec();
    let key_slice = unsafe {std::slice::from_raw_parts(key, key_length)}.to_vec();
    let to_decrypt_slice = unsafe { std::slice::from_raw_parts(to_decrypt, to_decrypt_length) }.to_vec();
    let mut plaintext = <CASAES128 as CASAES128Encryption>::decrypt_ciphertext(key_slice, nonce_slice, to_decrypt_slice);
    let capacity = plaintext.capacity();
    plaintext.reserve_exact(capacity);
    let result = AesBytesDecrypt {
        plaintext: plaintext.as_mut_ptr(),
        length: plaintext.len(),
    };
    std::mem::forget(plaintext);
    return result;
}

#[no_mangle]
pub extern "C" fn aes_128_decrypt_bytes_with_key_threadpool(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
) -> AesBytesDecrypt {
    let nonce_slice = unsafe { std::slice::from_raw_parts(nonce_key, nonce_key_length) }.to_vec();
    let key_slice = unsafe {std::slice::from_raw_parts(key, key_length)}.to_vec();
    let to_decrypt_slice = unsafe { std::slice::from_raw_parts(to_decrypt, to_decrypt_length) }.to_vec();
    let mut plaintext = <CASAES128 as CASAES128Encryption>::decrypt_ciphertext_threadpool(key_slice, nonce_slice, to_decrypt_slice);
    let capacity = plaintext.capacity();
    plaintext.reserve_exact(capacity);
    let result = AesBytesDecrypt {
        plaintext: plaintext.as_mut_ptr(),
        length: plaintext.len(),
    };
    std::mem::forget(plaintext);
    return result;
}

#[no_mangle]
pub extern "C" fn aes_256_decrypt_bytes_with_key(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
) -> AesBytesDecrypt {
    let nonce_slice = unsafe { std::slice::from_raw_parts(nonce_key, nonce_key_length) }.to_vec();
    let key_slice = unsafe {std::slice::from_raw_parts(key, key_length)}.to_vec();
    let to_decrypt_slice = unsafe { std::slice::from_raw_parts(to_decrypt, to_decrypt_length) }.to_vec();
    let mut plaintext = <CASAES256 as CASAES256Encryption>::decrypt_ciphertext(key_slice, nonce_slice, to_decrypt_slice);
    let capacity = plaintext.capacity();
    plaintext.reserve_exact(capacity);
    let result = AesBytesDecrypt {
        plaintext: plaintext.as_mut_ptr(),
        length: plaintext.len(),
    };
    std::mem::forget(plaintext);
    return result;
}

#[no_mangle]
pub extern "C" fn aes_256_decrypt_bytes_with_key_threadpool(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
) -> AesBytesDecrypt {
    let nonce_slice = unsafe { std::slice::from_raw_parts(nonce_key, nonce_key_length) }.to_vec();
    let key_slice = unsafe {std::slice::from_raw_parts(key, key_length)}.to_vec();
    let to_decrypt_slice = unsafe { std::slice::from_raw_parts(to_decrypt, to_decrypt_length) }.to_vec();
    let mut plaintext = <CASAES256 as CASAES256Encryption>::decrypt_ciphertext_threadpool(key_slice, nonce_slice, to_decrypt_slice);
    let capacity = plaintext.capacity();
    plaintext.reserve_exact(capacity);
    let result = AesBytesDecrypt {
        plaintext: plaintext.as_mut_ptr(),
        length: plaintext.len(),
    };
    std::mem::forget(plaintext);
    return result;
}
