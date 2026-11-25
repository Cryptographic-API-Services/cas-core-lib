use cas_lib::error::CasResult;
use cas_lib::symmetric::{aes::{CASAES128, CASAES256}, cas_symmetric_encryption::{CASAES128AadEncryption, CASAES128Encryption, CASAES256AadEncryption, CASAES256Encryption, CASAeadSeal}};
use std::ffi::c_uchar;

use crate::{helpers::{bytes_from_ffi, cas_error_code, export_bytes}, x25519};
#[cfg(test)]
use crate::helpers::take_bytes;

/// AES-GCM nonce from `aes_nonce`.
///
/// The caller owns `nonce` and frees it once with `free_bytes`.
#[repr(C)]
pub struct AesNonce {
    pub nonce: *mut c_uchar,
    pub length: usize
}

/// AES key from `aes_128_key` / `aes_256_key`.
///
/// The caller owns `key` (secret) and frees it once with `free_bytes`.
#[repr(C)]
pub struct AesKeyResult {
    pub key: *mut c_uchar,
    pub length: usize
}

/// AES-GCM ciphertext from `aes_128_encrypt_bytes_with_key` /
/// `aes_256_encrypt_bytes_with_key`.
///
/// The caller owns `ciphertext` and frees it once with `free_bytes`. It is
/// null when `error_code` is non-zero.
#[repr(C)]
pub struct AesBytesEncrypt {
    pub ciphertext: *mut c_uchar,
    pub length: usize,
    pub error_code: i32,
}

/// AES-GCM plaintext from `aes_128_decrypt_bytes_with_key` /
/// `aes_256_decrypt_bytes_with_key`.
///
/// The caller owns `plaintext` and frees it once with `free_bytes`. It is
/// null when `error_code` is non-zero.
#[repr(C)]
pub struct AesBytesDecrypt {
    pub plaintext: *mut c_uchar,
    pub length: usize,
    pub error_code: i32,
}

/// AES key derived by `aes_128_key_from_x25519_diffie_hellman_shared_secret`
/// / `aes_256_key_from_x25519_diffie_hellman_shared_secret`.
///
/// The caller owns `aes_key_ptr` (secret) and frees it once with `free_bytes`.
/// It is null when `error_code` is non-zero.
#[repr(C)]
pub struct AesNonceAndKeyFromX25519DiffieHellman {
    pub aes_key_ptr: *mut c_uchar,
    pub aes_key_ptr_length: usize,
    pub error_code: i32,
}

/// Derives an AES-256-GCM key from an X25519 shared secret and both parties'
/// public keys (HKDF-SHA256, bound to the cipher and to both public keys).
/// The public keys can be passed in either order, so both peers get the same
/// key. Returns `InvalidKey` (1) for a wrong-length or all-zero shared secret
/// or a wrong-length public key.
#[no_mangle]
pub extern "C" fn aes_256_key_from_x25519_diffie_hellman_shared_secret(
    shared_secret: *const c_uchar,
    shared_secret_length: usize,
    public_key_a: *const c_uchar,
    public_key_a_length: usize,
    public_key_b: *const c_uchar,
    public_key_b_length: usize,
) -> AesNonceAndKeyFromX25519DiffieHellman {
    let shared_secret_slice: Vec<u8> =
        unsafe { std::slice::from_raw_parts(shared_secret, shared_secret_length) }.to_vec();
    let public_key_a_slice: Vec<u8> =
        unsafe { std::slice::from_raw_parts(public_key_a, public_key_a_length) }.to_vec();
    let public_key_b_slice: Vec<u8> =
        unsafe { std::slice::from_raw_parts(public_key_b, public_key_b_length) }.to_vec();
    match <CASAES256 as CASAES256Encryption>::key_from_x25519_shared_secret(shared_secret_slice, public_key_a_slice, public_key_b_slice) {
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

/// Derives an AES-128-GCM key the same way as
/// [`aes_256_key_from_x25519_diffie_hellman_shared_secret`], with a
/// per-cipher label, so the two never give related keys.
#[no_mangle]
pub extern "C" fn aes_128_key_from_x25519_diffie_hellman_shared_secret(
    shared_secret: *const c_uchar,
    shared_secret_length: usize,
    public_key_a: *const c_uchar,
    public_key_a_length: usize,
    public_key_b: *const c_uchar,
    public_key_b_length: usize,
) -> AesNonceAndKeyFromX25519DiffieHellman {
    let shared_secret_slice: Vec<u8> =
        unsafe { std::slice::from_raw_parts(shared_secret, shared_secret_length) }.to_vec();
    let public_key_a_slice: Vec<u8> =
        unsafe { std::slice::from_raw_parts(public_key_a, public_key_a_length) }.to_vec();
    let public_key_b_slice: Vec<u8> =
        unsafe { std::slice::from_raw_parts(public_key_b, public_key_b_length) }.to_vec();
    match <CASAES128 as CASAES128Encryption>::key_from_x25519_shared_secret(shared_secret_slice, public_key_a_slice, public_key_b_slice) {
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

#[cfg(test)]
type X25519KeyDerivation = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize) -> AesNonceAndKeyFromX25519DiffieHellman;

#[cfg(test)]
fn x25519_derived_key(result: &AesNonceAndKeyFromX25519DiffieHellman) -> Vec<u8> {
    assert_eq!(0, result.error_code);
    unsafe { std::slice::from_raw_parts(result.aes_key_ptr, result.aes_key_ptr_length) }.to_vec()
}

/// Runs an Alice/Bob exchange in which each peer passes the public keys in the
/// opposite order. Returns (Alice's key, Bob's key, shared secret, Alice's
/// public key, Bob's public key).
#[cfg(test)]
fn x25519_exchange(derive: X25519KeyDerivation) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let alice = x25519::generate_secret_and_public_key();
    let bob = x25519::generate_secret_and_public_key();
    let alice_shared_secret = x25519::diffie_hellman(alice.secret_key, alice.secret_key_length, bob.public_key, bob.public_key_length);
    let bob_shared_secret = x25519::diffie_hellman(bob.secret_key, bob.secret_key_length, alice.public_key, alice.public_key_length);
    assert_eq!(0, alice_shared_secret.error_code);
    assert_eq!(0, bob_shared_secret.error_code);
    let shared_secret = unsafe { std::slice::from_raw_parts(alice_shared_secret.shared_secret, alice_shared_secret.shared_secret_length) }.to_vec();
    let bob_shared_secret_slice = unsafe { std::slice::from_raw_parts(bob_shared_secret.shared_secret, bob_shared_secret.shared_secret_length) };
    assert_eq!(shared_secret.as_slice(), bob_shared_secret_slice);
    let alice_public_key = unsafe { std::slice::from_raw_parts(alice.public_key, alice.public_key_length) }.to_vec();
    let bob_public_key = unsafe { std::slice::from_raw_parts(bob.public_key, bob.public_key_length) }.to_vec();

    let alice_key = x25519_derived_key(&derive(
        alice_shared_secret.shared_secret, alice_shared_secret.shared_secret_length,
        alice.public_key, alice.public_key_length,
        bob.public_key, bob.public_key_length,
    ));
    let bob_key = x25519_derived_key(&derive(
        bob_shared_secret.shared_secret, bob_shared_secret.shared_secret_length,
        bob.public_key, bob.public_key_length,
        alice.public_key, alice.public_key_length,
    ));
    (alice_key, bob_key, shared_secret, alice_public_key, bob_public_key)
}

#[test]
pub fn aes_256_key_and_nonce_from_x25519_diffie_hellman_shared_secret_test() {
    let (alice_key, bob_key, shared_secret, _, _) = x25519_exchange(aes_256_key_from_x25519_diffie_hellman_shared_secret);
    assert_eq!(32, alice_key.len());
    assert_eq!(alice_key, bob_key);
    // The key goes through HKDF: it is not the raw Diffie-Hellman output (#91).
    assert_ne!(shared_secret, alice_key);

    let password = "DontUseThisPassword";
    let password_cstr = password.as_bytes();
    let password_ptr = password.as_ptr();
    let nonce = CASAES256::generate_nonce();
    let nonce_ptr = nonce.as_ptr();
    let cipher_text_result = aes_256_encrypt_bytes_with_key(nonce_ptr, nonce.len(), alice_key.as_ptr(), alice_key.len(), password_ptr, password_cstr.len());
    let plain_text_result = aes_256_decrypt_bytes_with_key(nonce_ptr, nonce.len(), bob_key.as_ptr(), bob_key.len(), cipher_text_result.ciphertext, cipher_text_result.length);
    let plain_text_result_slice: &[u8] = unsafe {
         std::slice::from_raw_parts(
             plain_text_result.plaintext,
             plain_text_result.length,
         )
     };
     assert_eq!(password_cstr, plain_text_result_slice);
}

#[test]
pub fn aes_128_key_from_x25519_diffie_hellman_shared_secret_test() {
    let (alice_key, bob_key, shared_secret, _, _) = x25519_exchange(aes_128_key_from_x25519_diffie_hellman_shared_secret);
    assert_eq!(16, alice_key.len());
    assert_eq!(alice_key, bob_key);
    assert_ne!(&shared_secret[..16], alice_key.as_slice());

    let password = "DontUseThisPassword";
    let password_cstr = password.as_bytes();
    let password_ptr = password.as_ptr();
    let nonce = CASAES128::generate_nonce();
    let nonce_ptr = nonce.as_ptr();
    let cipher_text_result = aes_128_encrypt_bytes_with_key(nonce_ptr, nonce.len(), alice_key.as_ptr(), alice_key.len(), password_ptr, password_cstr.len());
    let plain_text_result = aes_128_decrypt_bytes_with_key(nonce_ptr, nonce.len(), bob_key.as_ptr(), bob_key.len(), cipher_text_result.ciphertext, cipher_text_result.length);
    let plain_text_result_slice: &[u8] = unsafe {
        std::slice::from_raw_parts(
            plain_text_result.plaintext,
            plain_text_result.length,
        )
    };
    assert_eq!(password_cstr, plain_text_result_slice);
}

#[test]
pub fn x25519_derived_keys_are_bound_to_cipher_and_public_keys_test() {
    let (_, _, shared_secret, alice_public_key, bob_public_key) = x25519_exchange(aes_256_key_from_x25519_diffie_hellman_shared_secret);
    let derive = |f: X25519KeyDerivation, a: &[u8], b: &[u8]| {
        x25519_derived_key(&f(shared_secret.as_ptr(), shared_secret.len(), a.as_ptr(), a.len(), b.as_ptr(), b.len()))
    };
    let key_256 = derive(aes_256_key_from_x25519_diffie_hellman_shared_secret, &alice_public_key, &bob_public_key);
    let key_128 = derive(aes_128_key_from_x25519_diffie_hellman_shared_secret, &alice_public_key, &bob_public_key);
    assert_ne!(&key_256[..16], key_128.as_slice());

    // A substituted public key changes the derived key.
    let mallory = x25519::generate_secret_and_public_key();
    let mallory_public_key = unsafe { std::slice::from_raw_parts(mallory.public_key, mallory.public_key_length) }.to_vec();
    let substituted = derive(aes_256_key_from_x25519_diffie_hellman_shared_secret, &alice_public_key, &mallory_public_key);
    assert_ne!(key_256, substituted);
}

#[test]
pub fn x25519_key_derivation_rejects_bad_inputs_test() {
    let invalid_key = cas_error_code(&cas_lib::error::CasError::InvalidKey);
    let secret = [1u8; 32];
    let zero_secret = [0u8; 32];
    let short_secret = [1u8; 31];
    let public_key = [9u8; 32];
    let short_public_key = [9u8; 31];
    let derivations: [X25519KeyDerivation; 2] = [
        aes_256_key_from_x25519_diffie_hellman_shared_secret,
        aes_128_key_from_x25519_diffie_hellman_shared_secret,
    ];
    for derive in derivations {
        for (s, a, b) in [
            (&zero_secret[..], &public_key[..], &public_key[..]),
            (&short_secret[..], &public_key[..], &public_key[..]),
            (&secret[..], &short_public_key[..], &public_key[..]),
            (&secret[..], &public_key[..], &short_public_key[..]),
        ] {
            let result = derive(s.as_ptr(), s.len(), a.as_ptr(), a.len(), b.as_ptr(), b.len());
            assert!(result.aes_key_ptr.is_null());
            assert_eq!(0, result.aes_key_ptr_length);
            assert_eq!(invalid_key, result.error_code);
        }
    }
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

fn aes_encrypt_result(result: CasResult<Vec<u8>>) -> AesBytesEncrypt {
    match result {
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

fn aes_decrypt_result(result: CasResult<Vec<u8>>) -> AesBytesDecrypt {
    match result {
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

/// Encrypts `plaintext` with AES-128-GCM under a fresh random nonce and returns
/// `nonce || ciphertext || tag`. This is the recommended way to encrypt: the
/// caller never handles a nonce, so it cannot reuse one. Rotate the key well
/// before about 2^32 messages. `aad` may be empty (a null pointer is accepted
/// when `aad_length` is 0); the same AAD must be passed to `aes_128_open`.
#[no_mangle]
pub extern "C" fn aes_128_seal(
    key: *const c_uchar,
    key_length: usize,
    plaintext: *const c_uchar,
    plaintext_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesBytesEncrypt {
    aes_encrypt_result((|| {
        let key = bytes_from_ffi(key, key_length)?;
        let plaintext = bytes_from_ffi(plaintext, plaintext_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES128 as CASAeadSeal>::seal(key, plaintext, Some(aad))
    })())
}

/// Decrypts a `nonce || ciphertext || tag` blob produced by `aes_128_seal`.
/// A blob shorter than nonce + tag is `InvalidInput`; a tampered blob or the
/// wrong AAD is `DecryptionFailed`.
#[no_mangle]
pub extern "C" fn aes_128_open(
    key: *const c_uchar,
    key_length: usize,
    sealed: *const c_uchar,
    sealed_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesBytesDecrypt {
    aes_decrypt_result((|| {
        let key = bytes_from_ffi(key, key_length)?;
        let sealed = bytes_from_ffi(sealed, sealed_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES128 as CASAeadSeal>::open(key, sealed, Some(aad))
    })())
}

/// AES-256-GCM version of `aes_128_seal`.
#[no_mangle]
pub extern "C" fn aes_256_seal(
    key: *const c_uchar,
    key_length: usize,
    plaintext: *const c_uchar,
    plaintext_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesBytesEncrypt {
    aes_encrypt_result((|| {
        let key = bytes_from_ffi(key, key_length)?;
        let plaintext = bytes_from_ffi(plaintext, plaintext_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES256 as CASAeadSeal>::seal(key, plaintext, Some(aad))
    })())
}

/// AES-256-GCM version of `aes_128_open`.
#[no_mangle]
pub extern "C" fn aes_256_open(
    key: *const c_uchar,
    key_length: usize,
    sealed: *const c_uchar,
    sealed_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesBytesDecrypt {
    aes_decrypt_result((|| {
        let key = bytes_from_ffi(key, key_length)?;
        let sealed = bytes_from_ffi(sealed, sealed_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES256 as CASAeadSeal>::open(key, sealed, Some(aad))
    })())
}

/// `aes_128_encrypt_bytes_with_key` with additional authenticated data. Returns
/// `ciphertext || tag`. The caller supplies the nonce and must never reuse it
/// under the same key; prefer `aes_128_seal`.
#[no_mangle]
pub extern "C" fn aes_128_encrypt_bytes_with_aad(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesBytesEncrypt {
    aes_encrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_encrypt = bytes_from_ffi(to_encrypt, to_encrypt_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES128 as CASAES128AadEncryption>::encrypt_plaintext_with_aad(key, nonce, to_encrypt, aad)
    })())
}

/// `aes_128_decrypt_bytes_with_key` with additional authenticated data. The
/// wrong AAD is `DecryptionFailed`.
#[no_mangle]
pub extern "C" fn aes_128_decrypt_bytes_with_aad(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesBytesDecrypt {
    aes_decrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_decrypt = bytes_from_ffi(to_decrypt, to_decrypt_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES128 as CASAES128AadEncryption>::decrypt_ciphertext_with_aad(key, nonce, to_decrypt, aad)
    })())
}

/// AES-256-GCM version of `aes_128_encrypt_bytes_with_aad`.
#[no_mangle]
pub extern "C" fn aes_256_encrypt_bytes_with_aad(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesBytesEncrypt {
    aes_encrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_encrypt = bytes_from_ffi(to_encrypt, to_encrypt_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES256 as CASAES256AadEncryption>::encrypt_plaintext_with_aad(key, nonce, to_encrypt, aad)
    })())
}

/// AES-256-GCM version of `aes_128_decrypt_bytes_with_aad`.
#[no_mangle]
pub extern "C" fn aes_256_decrypt_bytes_with_aad(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesBytesDecrypt {
    aes_decrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_decrypt = bytes_from_ffi(to_decrypt, to_decrypt_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES256 as CASAES256AadEncryption>::decrypt_ciphertext_with_aad(key, nonce, to_decrypt, aad)
    })())
}

#[cfg(test)]
type AesSealFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize) -> AesBytesEncrypt;
#[cfg(test)]
type AesOpenFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize) -> AesBytesDecrypt;

// Runs the seal/open checks against one key size.
#[cfg(test)]
fn check_aes_seal_open(key: Vec<u8>, nonce_len: usize, seal: AesSealFn, open: AesOpenFn) {
    use cas_lib::error::CasError;
    let plaintext = b"WelcomeHome".to_vec();
    let aad = b"header".to_vec();
    let do_open = |sealed: &[u8], aad: &[u8]| open(key.as_ptr(), key.len(), sealed.as_ptr(), sealed.len(), aad.as_ptr(), aad.len());

    let sealed = seal(key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_eq!(0, sealed.error_code);
    let sealed = take_bytes(sealed.ciphertext, sealed.length);
    assert_eq!(nonce_len + plaintext.len() + 16, sealed.len());

    // Round trip.
    let opened = do_open(&sealed, &aad);
    assert_eq!(0, opened.error_code);
    assert_eq!(plaintext, take_bytes(opened.plaintext, opened.length));

    // Wrong or missing AAD.
    for wrong_aad in [&b"other header"[..], &[][..]] {
        let opened = do_open(&sealed, wrong_aad);
        assert!(opened.plaintext.is_null());
        assert_eq!(cas_error_code(&CasError::DecryptionFailed), opened.error_code);
    }

    // A flipped bit in the nonce, the ciphertext or the tag.
    for index in [0, nonce_len, sealed.len() - 1] {
        let mut tampered = sealed.clone();
        tampered[index] ^= 0x01;
        let opened = do_open(&tampered, &aad);
        assert!(opened.plaintext.is_null());
        assert_eq!(cas_error_code(&CasError::DecryptionFailed), opened.error_code);
    }

    // Too short to hold a nonce and a tag.
    let opened = do_open(&sealed[..nonce_len + 15], &aad);
    assert_eq!(cas_error_code(&CasError::InvalidInput), opened.error_code);

    // A fresh nonce per call.
    let sealed_again = seal(key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_ne!(sealed, take_bytes(sealed_again.ciphertext, sealed_again.length));

    // Empty AAD may be passed as a null pointer.
    let sealed = seal(key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), std::ptr::null(), 0);
    let sealed = take_bytes(sealed.ciphertext, sealed.length);
    let opened = open(key.as_ptr(), key.len(), sealed.as_ptr(), sealed.len(), std::ptr::null(), 0);
    assert_eq!(plaintext, take_bytes(opened.plaintext, opened.length));

    // A null pointer with a non-zero length is reported, not a panic.
    let sealed = seal(key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), std::ptr::null(), 4);
    assert!(sealed.ciphertext.is_null());
    assert_eq!(cas_error_code(&CasError::InvalidInput), sealed.error_code);

    // Wrong key length.
    let short_key = vec![0u8; 5];
    let sealed = seal(short_key.as_ptr(), short_key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_eq!(cas_error_code(&CasError::InvalidKey), sealed.error_code);
}

#[test]
fn aes_128_seal_open_test() {
    let key = aes_128_key();
    check_aes_seal_open(take_bytes(key.key, key.length), CASAES128::NONCE_LEN, aes_128_seal, aes_128_open);
}

#[test]
fn aes_256_seal_open_test() {
    let key = aes_256_key();
    check_aes_seal_open(take_bytes(key.key, key.length), CASAES256::NONCE_LEN, aes_256_seal, aes_256_open);
}

#[test]
fn aes_256_seal_output_opens_with_caller_nonce_api_test() {
    let key = aes_256_key();
    let key = take_bytes(key.key, key.length);
    let plaintext = b"WelcomeHome".to_vec();
    let aad = b"header".to_vec();
    let sealed = aes_256_seal(key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    let sealed = take_bytes(sealed.ciphertext, sealed.length);
    let (nonce, ciphertext) = sealed.split_at(CASAES256::NONCE_LEN);
    let decrypted = aes_256_decrypt_bytes_with_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), ciphertext.as_ptr(), ciphertext.len(), aad.as_ptr(), aad.len());
    assert_eq!(0, decrypted.error_code);
    assert_eq!(plaintext, take_bytes(decrypted.plaintext, decrypted.length));
}

#[cfg(test)]
type AesEncryptAadFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize) -> AesBytesEncrypt;
#[cfg(test)]
type AesDecryptAadFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize) -> AesBytesDecrypt;
#[cfg(test)]
type AesDecryptFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize) -> AesBytesDecrypt;

// Runs the caller-nonce AAD checks against one key size.
#[cfg(test)]
fn check_aes_aad(key: Vec<u8>, encrypt: AesEncryptAadFn, decrypt: AesDecryptAadFn, decrypt_without_aad: AesDecryptFn) {
    use cas_lib::error::CasError;
    let nonce = aes_nonce();
    let nonce = take_bytes(nonce.nonce, nonce.length);
    let plaintext = b"WelcomeHome".to_vec();
    let aad = b"record-42".to_vec();
    let do_decrypt = |ciphertext: &[u8], aad: &[u8]| decrypt(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), ciphertext.as_ptr(), ciphertext.len(), aad.as_ptr(), aad.len());

    let encrypted = encrypt(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_eq!(0, encrypted.error_code);
    let ciphertext = take_bytes(encrypted.ciphertext, encrypted.length);

    // Round trip.
    let decrypted = do_decrypt(&ciphertext, &aad);
    assert_eq!(0, decrypted.error_code);
    assert_eq!(plaintext, take_bytes(decrypted.plaintext, decrypted.length));

    // Wrong or missing AAD.
    for wrong_aad in [&b"record-43"[..], &[][..]] {
        let decrypted = do_decrypt(&ciphertext, wrong_aad);
        assert!(decrypted.plaintext.is_null());
        assert_eq!(cas_error_code(&CasError::DecryptionFailed), decrypted.error_code);
    }

    // The non-AAD decrypt does not accept a ciphertext bound to AAD.
    let decrypted = decrypt_without_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), ciphertext.as_ptr(), ciphertext.len());
    assert_eq!(cas_error_code(&CasError::DecryptionFailed), decrypted.error_code);

    // A flipped bit in the ciphertext or the tag.
    for index in [0, ciphertext.len() - 1] {
        let mut tampered = ciphertext.clone();
        tampered[index] ^= 0x01;
        let decrypted = do_decrypt(&tampered, &aad);
        assert!(decrypted.plaintext.is_null());
        assert_eq!(cas_error_code(&CasError::DecryptionFailed), decrypted.error_code);
    }

    // Wrong nonce length.
    let short_nonce = vec![0u8; 5];
    let encrypted = encrypt(short_nonce.as_ptr(), short_nonce.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_eq!(cas_error_code(&CasError::InvalidNonce), encrypted.error_code);
}

#[test]
fn aes_128_encrypt_decrypt_with_aad_test() {
    let key = aes_128_key();
    check_aes_aad(take_bytes(key.key, key.length), aes_128_encrypt_bytes_with_aad, aes_128_decrypt_bytes_with_aad, aes_128_decrypt_bytes_with_key);
}

#[test]
fn aes_256_encrypt_decrypt_with_aad_test() {
    let key = aes_256_key();
    check_aes_aad(take_bytes(key.key, key.length), aes_256_encrypt_bytes_with_aad, aes_256_decrypt_bytes_with_aad, aes_256_decrypt_bytes_with_key);
}
