//! Frees every kind of single-buffer and string result the FFI hands out, the
//! way a consumer SDK would. The multi-buffer results are covered next to their
//! `free_<struct>` functions (x25519, ed25519, hpke, rsa, pqc).

use std::ffi::{c_uchar, CString};

use crate::helpers::{free_bytes, free_cstring};
use crate::{aes, ascon_aead, blake2, hmac, sha, x25519, zstd};
use crate::password_hashers::{argon2, bcrypt, scrypt};

/// Same layout as the `{ ptr, length }` results whose fields are private
/// (`Ascon128Key`, `Ascon128Nonce`). `transmute` fails to compile if the sizes
/// ever differ.
#[repr(C)]
struct BytesResult {
    ptr: *mut c_uchar,
    length: usize,
}

/// Same layout as the `{ ptr, length, error_code }` results whose fields are
/// private (`Ascon128EncryptResult`, `Ascon128DecryptResult`, `ZstdCompressResult`).
#[repr(C)]
struct BytesErrorResult {
    ptr: *mut c_uchar,
    length: usize,
    error_code: i32,
}

#[test]
fn free_aes_results_test() {
    let plaintext = b"free every AES result".to_vec();
    let nonce = aes::aes_nonce();
    for key in [aes::aes_128_key(), aes::aes_256_key()] {
        let is_128 = key.length == 16;
        let encrypt = if is_128 { aes::aes_128_encrypt_bytes_with_key } else { aes::aes_256_encrypt_bytes_with_key };
        let decrypt = if is_128 { aes::aes_128_decrypt_bytes_with_key } else { aes::aes_256_decrypt_bytes_with_key };
        let ciphertext = encrypt(nonce.nonce, nonce.length, key.key, key.length, plaintext.as_ptr(), plaintext.len());
        assert_eq!(0, ciphertext.error_code);
        let decrypted = decrypt(nonce.nonce, nonce.length, key.key, key.length, ciphertext.ciphertext, ciphertext.length);
        assert_eq!(0, decrypted.error_code);
        assert_eq!(plaintext, unsafe { std::slice::from_raw_parts(decrypted.plaintext, decrypted.length) });
        free_bytes(decrypted.plaintext);
        free_bytes(ciphertext.ciphertext);
        free_bytes(key.key);
    }
    free_bytes(nonce.nonce);

    let alice = x25519::generate_secret_and_public_key();
    let bob = x25519::generate_secret_and_public_key();
    let shared_secret = x25519::diffie_hellman(alice.secret_key, alice.secret_key_length, bob.public_key, bob.public_key_length);
    for derive in [
        aes::aes_128_key_from_x25519_diffie_hellman_shared_secret,
        aes::aes_256_key_from_x25519_diffie_hellman_shared_secret,
    ] {
        let derived = derive(shared_secret.shared_secret, shared_secret.shared_secret_length);
        assert_eq!(0, derived.error_code);
        free_bytes(derived.aes_key_ptr);
    }
    free_bytes(shared_secret.shared_secret);
    for keys in [alice, bob] {
        free_bytes(keys.secret_key);
        free_bytes(keys.public_key);
    }
}

#[test]
fn free_ascon_results_test() {
    let plaintext = b"free every Ascon result".to_vec();
    let key: BytesResult = unsafe { std::mem::transmute(ascon_aead::ascon_128_key()) };
    let nonce: BytesResult = unsafe { std::mem::transmute(ascon_aead::ascon_128_nonce()) };
    let ciphertext: BytesErrorResult = unsafe {
        std::mem::transmute(ascon_aead::ascon_128_encrypt(nonce.ptr, nonce.length, key.ptr, key.length, plaintext.as_ptr(), plaintext.len()))
    };
    assert_eq!(0, ciphertext.error_code);
    let decrypted: BytesErrorResult = unsafe {
        std::mem::transmute(ascon_aead::ascon_128_decrypt(nonce.ptr, nonce.length, key.ptr, key.length, ciphertext.ptr, ciphertext.length))
    };
    assert_eq!(0, decrypted.error_code);
    assert_eq!(plaintext, unsafe { std::slice::from_raw_parts(decrypted.ptr, decrypted.length) });
    free_bytes(decrypted.ptr);
    free_bytes(ciphertext.ptr);
    free_bytes(nonce.ptr);
    free_bytes(key.ptr);
}

#[test]
fn free_hash_results_test() {
    let data = b"free every hash result".to_vec();
    for hash in [blake2::blake2_256_bytes, blake2::blake2_512_bytes] {
        let digest = hash(data.as_ptr(), data.len());
        assert!(digest.length > 0);
        free_bytes(digest.result_bytes_ptr);
    }
    for hash in [sha::sha2_256_bytes, sha::sha2_512_bytes, sha::sha3_256_bytes, sha::sha3_512_bytes] {
        let digest = hash(data.as_ptr(), data.len());
        assert!(digest.length > 0);
        free_bytes(digest.result_bytes_ptr);
    }

    let key = b"hmac key".to_vec();
    let tag = hmac::hmac_sign_bytes(key.as_ptr(), key.len(), data.as_ptr(), data.len());
    assert_eq!(0, tag.error_code);
    free_bytes(tag.result_bytes_ptr);
}

#[test]
fn free_zstd_results_test() {
    let data = vec![42u8; 4096];
    let compressed: BytesErrorResult = unsafe { std::mem::transmute(zstd::compress(data.as_ptr(), data.len(), 3)) };
    assert_eq!(0, compressed.error_code);
    let decompressed: BytesErrorResult = unsafe { std::mem::transmute(zstd::decompress(compressed.ptr, compressed.length)) };
    assert_eq!(0, decompressed.error_code);
    assert_eq!(data, unsafe { std::slice::from_raw_parts(decompressed.ptr, decompressed.length) });
    free_bytes(decompressed.ptr);
    free_bytes(compressed.ptr);
}

#[test]
fn free_password_hasher_results_test() {
    let password = CString::new("DoNotUseThisPassword").unwrap();
    for hash in [argon2::argon2_hash, bcrypt::bcrypt_hash, scrypt::scrypt_hash] {
        let hashed = hash(password.as_ptr());
        assert_eq!(0, hashed.error_code);
        assert!(!hashed.value.is_null());
        free_cstring(hashed.value);
    }

    let hashed = argon2::argon2_hash_password_parameters(1024, 2, 1, password.as_ptr());
    assert_eq!(0, hashed.error_code);
    for derive in [argon2::argon2_derive_aes_128_key, argon2::argon2_derive_aes_256_key] {
        let key = derive(hashed.value);
        assert_eq!(0, key.error_code);
        free_bytes(key.key);
    }
    free_cstring(hashed.value);
}

#[test]
fn free_error_results_test() {
    // Failed calls return null buffers; freeing them is a no-op.
    let short_key = vec![0u8; 3];
    let nonce = aes::aes_nonce();
    let failed = aes::aes_256_encrypt_bytes_with_key(nonce.nonce, nonce.length, short_key.as_ptr(), short_key.len(), short_key.as_ptr(), short_key.len());
    assert_ne!(0, failed.error_code);
    assert!(failed.ciphertext.is_null());
    free_bytes(failed.ciphertext);
    free_bytes(nonce.nonce);

    let garbage = vec![0u8; 16];
    let failed: BytesErrorResult = unsafe { std::mem::transmute(zstd::decompress(garbage.as_ptr(), garbage.len())) };
    assert_ne!(0, failed.error_code);
    free_bytes(failed.ptr);
}
