use cas_lib::symmetric::{aes::{CASAES128, CASAES256}, cas_symmetric_encryption::{CASAES128Encryption, CASAES256Encryption}};
use std::ffi::c_uchar;

use crate::{helpers::{cas_error_code, export_bytes}, x25519};

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
    pub error_code: i32,
}

#[repr(C)]
pub struct AesBytesDecrypt {
    pub plaintext: *mut c_uchar,
    pub length: usize,
    pub error_code: i32,
}

#[repr(C)]
pub struct AesNonceAndKeyFromX25519DiffieHellman {
    pub aes_key_ptr: *mut c_uchar,
    pub aes_key_ptr_length: usize,
    pub error_code: i32,
}

#[no_mangle]
pub extern "C" fn aes_256_key_from_x25519_diffie_hellman_shared_secret(
    shared_secret: *const c_uchar,
    shared_secret_length: usize,
) -> AesNonceAndKeyFromX25519DiffieHellman {
    let shared_secret_slice: Vec<u8> =
        unsafe { std::slice::from_raw_parts(shared_secret, shared_secret_length) }.to_vec();

    match <CASAES256 as CASAES256Encryption>::key_from_vec(shared_secret_slice) {
        Ok(aes_key) => {
            let result = AesNonceAndKeyFromX25519DiffieHellman {
                aes_key_ptr: export_bytes(&aes_key),
                aes_key_ptr_length: aes_key.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => AesNonceAndKeyFromX25519DiffieHellman {
            aes_key_ptr: std::ptr::null_mut(),
            aes_key_ptr_length: 0,
            error_code: cas_error_code(&e),
        },
    }
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

    let alice_aes = aes_256_key_from_x25519_diffie_hellman_shared_secret(
        alice_secret_key,
        alice_shared_secret.shared_secret_length,
    );
    
    let bob_aes = aes_256_key_from_x25519_diffie_hellman_shared_secret(
        bob_shared_secret.shared_secret,
        bob_shared_secret.shared_secret_length,
    );

    let password = "DontUseThisPassword";
    let password_cstr = password.as_bytes();
    let password_ptr = password.as_ptr();
    let nonce = CASAES256::generate_nonce();
    let nonce_ptr = nonce.as_ptr();
    let cipher_text_result = aes_256_encrypt_bytes_with_key(nonce_ptr, nonce.len(), alice_aes.aes_key_ptr, alice_aes.aes_key_ptr_length, password_ptr, password_cstr.len());
    let plain_text_result = aes_256_decrypt_bytes_with_key(nonce_ptr, nonce.len(), bob_aes.aes_key_ptr, bob_aes.aes_key_ptr_length, cipher_text_result.ciphertext, cipher_text_result.length);
    let plain_text_result_slice: &[u8] = unsafe {
         std::slice::from_raw_parts(
             plain_text_result.plaintext,
             plain_text_result.length,
         )
     };
     assert_eq!(password_cstr, plain_text_result_slice);
}

#[no_mangle]
pub extern "C" fn aes_128_key_from_x25519_diffie_hellman_shared_secret(
    shared_secret: *const c_uchar,
    shared_secret_length: usize,
) -> AesNonceAndKeyFromX25519DiffieHellman {
    let shared_secret_slice: Vec<u8> =
        unsafe { std::slice::from_raw_parts(shared_secret, shared_secret_length) }.to_vec();
    match <CASAES128 as CASAES128Encryption>::key_from_x25519_shared_secret(shared_secret_slice) {
        Ok(aes_key) => {
            let result = AesNonceAndKeyFromX25519DiffieHellman {
                aes_key_ptr: export_bytes(&aes_key),
                aes_key_ptr_length: aes_key.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => AesNonceAndKeyFromX25519DiffieHellman {
            aes_key_ptr: std::ptr::null_mut(),
            aes_key_ptr_length: 0,
            error_code: cas_error_code(&e),
        },
    }
}



#[test]
pub fn aes_128_key_from_x25519_diffie_hellman_shared_secret_test() {
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

    let alice_aes = aes_128_key_from_x25519_diffie_hellman_shared_secret(
        alice_secret_key,
        alice_shared_secret.shared_secret_length,
    );
    
    let bob_aes = aes_128_key_from_x25519_diffie_hellman_shared_secret(
        bob_shared_secret.shared_secret,
        bob_shared_secret.shared_secret_length,
    );

    let password = "DontUseThisPassword";
    let password_cstr = password.as_bytes();
    let password_ptr = password.as_ptr();
    let nonce = CASAES128::generate_nonce();
    let nonce_ptr = nonce.as_ptr();
    let cipher_text_result = aes_128_encrypt_bytes_with_key(nonce_ptr, nonce.len(), alice_aes.aes_key_ptr, alice_aes.aes_key_ptr_length, password_ptr, password_cstr.len());
    let plain_text_result = aes_128_decrypt_bytes_with_key(nonce_ptr, nonce.len(), bob_aes.aes_key_ptr, bob_aes.aes_key_ptr_length, cipher_text_result.ciphertext, cipher_text_result.length);
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
    let random_bytes = <CASAES256 as CASAES256Encryption>::generate_nonce();
    let result = AesNonce {
        nonce: export_bytes(&random_bytes),
        length: random_bytes.len()
    };
    result
}



#[no_mangle]
pub extern "C" fn aes_256_key() -> AesKeyResult {
    let key = <CASAES256 as CASAES256Encryption>::generate_key();
    let result = AesKeyResult {
        key: export_bytes(&key),
        length: key.len()
    };
    result
}



#[no_mangle]
pub extern "C" fn aes_128_key() -> AesKeyResult {
    let key = <CASAES128 as CASAES128Encryption>::generate_key();
    let result = AesKeyResult {
        key: export_bytes(&key),
        length: key.len()
    };
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
    match <CASAES128 as CASAES128Encryption>::encrypt_plaintext(key_slice, nonce_slice, to_encrypt_slice) {
        Ok(ciphertext) => {
            let result = AesBytesEncrypt {
                ciphertext: export_bytes(&ciphertext),
                length: ciphertext.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => AesBytesEncrypt {
            ciphertext: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
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
    match <CASAES256 as CASAES256Encryption>::encrypt_plaintext(key_slice, nonce_slice, to_encrypt_slice) {
        Ok(ciphertext) => {
            let result = AesBytesEncrypt {
                ciphertext: export_bytes(&ciphertext),
                length: ciphertext.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => AesBytesEncrypt {
            ciphertext: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
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
    match <CASAES128 as CASAES128Encryption>::decrypt_ciphertext(key_slice, nonce_slice, to_decrypt_slice) {
        Ok(plaintext) => {
            let result = AesBytesDecrypt {
                plaintext: export_bytes(&plaintext),
                length: plaintext.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => AesBytesDecrypt {
            plaintext: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
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
    match <CASAES256 as CASAES256Encryption>::decrypt_ciphertext(key_slice, nonce_slice, to_decrypt_slice) {
        Ok(plaintext) => {
            let result = AesBytesDecrypt {
                plaintext: export_bytes(&plaintext),
                length: plaintext.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => AesBytesDecrypt {
            plaintext: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}
