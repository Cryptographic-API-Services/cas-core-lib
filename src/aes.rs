use aes_gcm::{
    aead::{generic_array::GenericArray, AeadMut, OsRng},
    Aes128Gcm, Aes256Gcm, Key, KeyInit, Nonce,
};
use rand::RngCore;
use rand_07::AsByteSliceMut;
use std::ffi::{c_char, c_uchar, CStr, CString};

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
    let shared_secret_slice: &[u8] =
        unsafe { std::slice::from_raw_parts(shared_secret, shared_secret_length) };

        let mut aes_nonce = Vec::with_capacity(12);
        aes_nonce.resize(12, 0);
        aes_nonce.copy_from_slice(&shared_secret_slice[..12]);
        let capacity = aes_nonce.capacity();
        aes_nonce.reserve_exact(capacity);
        
        let mut aes_key = Key::<Aes256Gcm>::from_slice(&shared_secret_slice).to_vec();
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


    
    let alice_public_key_cstr = unsafe { CString::from_raw(alice_aes.aes_key_ptr) };
    let alice_public_key_ptr = alice_public_key_cstr.as_bytes_with_nul().as_ptr() as *const c_char;

    let password = "DontUseThisPassword";
    let password_cstr = password.as_bytes();
    let password_ptr = password.as_ptr();
    let cipher_text_result = aes_256_encrypt_bytes_with_key(alice_aes.aes_nonce_ptr, alice_aes.aes_nonce_ptr_length, alice_public_key_ptr, password_ptr, password_cstr.len());
    let plain_text_result = aes_256_decrypt_bytes_with_key(bob_aes.aes_nonce_ptr, bob_aes.aes_nonce_ptr_length, bob_aes.aes_key_ptr, cipher_text_result.ciphertext, cipher_text_result.length);
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
    let shared_secret_slice: &[u8] =
        unsafe { std::slice::from_raw_parts(shared_secret, shared_secret_length) };

    let mut shorted_shared_secret: [u8; 16] = Default::default();
    shorted_shared_secret.copy_from_slice(&shared_secret_slice[..16]);
    let mut aes_nonce = Vec::with_capacity(12);
    aes_nonce.resize(12, 0);
    aes_nonce.copy_from_slice(&shared_secret_slice[..12]);
    let capacity = aes_nonce.capacity();
    aes_nonce.reserve_exact(capacity);

    let mut aes_key = Key::<Aes128Gcm>::from_slice(&shorted_shared_secret).to_vec();
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

    
    let alice_public_key_cstr = unsafe { CString::from_raw(alice_aes.aes_key_ptr) };
    let alice_public_key_ptr = alice_public_key_cstr.as_bytes_with_nul().as_ptr() as *const c_char;

    let password = "DontUseThisPassword";
    let password_cstr = password.as_bytes();
    let password_ptr = password.as_ptr();
    let cipher_text_result = aes_128_encrypt_bytes_with_key(alice_aes.aes_nonce_ptr, alice_aes.aes_nonce_ptr_length, alice_public_key_ptr, password_ptr, password_cstr.len());
    let plain_text_result = aes_128_decrypt_bytes_with_key(bob_aes.aes_nonce_ptr, bob_aes.aes_nonce_ptr_length, bob_aes.aes_key_ptr, cipher_text_result.ciphertext, cipher_text_result.length);
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
    let mut rng = &mut OsRng;
    let mut random_bytes = Vec::with_capacity(12);
    random_bytes.resize(12, 0);
    rng.fill_bytes(&mut random_bytes);
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
    let mut key = Aes256Gcm::generate_key(&mut OsRng).to_vec();
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
    let mut key = Aes128Gcm::generate_key(&mut OsRng).to_vec();
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
    let nonce_slice = unsafe { std::slice::from_raw_parts(nonce_key, nonce_key_length) };
    let key_slice = unsafe {std::slice::from_raw_parts(key, key_length)};
    let to_encrypt_slice: &[u8] =
        unsafe { std::slice::from_raw_parts(to_encrypt, to_encrypt_length) };
    let key = GenericArray::from_slice(key_slice);
    let mut cipher = Aes128Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_slice); // 96-bits; unique per message
    let mut ciphertext: Vec<u8> = cipher.encrypt(nonce, to_encrypt_slice.as_ref()).unwrap();
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
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
) -> AesBytesEncrypt {
    let nonce_slice = unsafe { std::slice::from_raw_parts(nonce_key, nonce_key_length) };
    let key_slice = unsafe {std::slice::from_raw_parts(key, key_length)};
    let to_decrypt_slice = unsafe { std::slice::from_raw_parts(to_decrypt, to_decrypt_length) };
    let key = GenericArray::from_slice(key_slice);
    let mut cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_slice); // 96-bits; unique per message
    let mut ciphertext = cipher.encrypt(nonce, to_decrypt_slice).unwrap();
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
    let nonce_slice = unsafe { std::slice::from_raw_parts(nonce_key, nonce_key_length) };
    let key_slice = unsafe {std::slice::from_raw_parts(key, key_length)};
    let to_decrypt_slice = unsafe { std::slice::from_raw_parts(to_decrypt, to_decrypt_length) };
    let key = GenericArray::from_slice(key_slice);
    let mut cipher = Aes128Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_slice); // 96-bits; unique per message
    let mut plaintext = cipher.decrypt(nonce, to_decrypt_slice).unwrap();
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
    let nonce_slice = unsafe { std::slice::from_raw_parts(nonce_key, nonce_key_length) };
    let key_slice = unsafe {std::slice::from_raw_parts(key, key_length)};
    let to_decrypt_slice = unsafe { std::slice::from_raw_parts(to_decrypt, to_decrypt_length) };
    let key = GenericArray::from_slice(key_slice);
    let mut cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_slice); // 96-bits; unique per message
    let mut plaintext = cipher.decrypt(nonce, to_decrypt_slice).unwrap();
    let capacity = plaintext.capacity();
    plaintext.reserve_exact(capacity);
    let result = AesBytesDecrypt {
        plaintext: plaintext.as_mut_ptr(),
        length: plaintext.len(),
    };
    std::mem::forget(plaintext);
    return result;
}
