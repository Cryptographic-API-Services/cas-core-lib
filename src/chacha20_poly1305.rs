use cas_lib::error::CasResult;
use cas_lib::symmetric::cas_symmetric_encryption::{CASAeadSeal, Chacha20Poly1305AadEncryption, Chacha20Poly1305Encryption};
use cas_lib::symmetric::chacha20poly1305::CASChacha20Poly1305;
use std::ffi::c_uchar;

use crate::helpers::{bytes_from_ffi, cas_error_code, export_bytes};
#[cfg(test)]
use crate::helpers::take_bytes;

#[repr(C)]
pub struct ChaCha20Poly1305Nonce {
    pub nonce: *mut c_uchar,
    pub length: usize,
    /// `0` on success. Generation takes no caller input.
    pub error_code: i32,
}

#[repr(C)]
pub struct ChaCha20Poly1305Key {
    pub key: *mut c_uchar,
    pub length: usize,
    /// `0` on success. Generation takes no caller input.
    pub error_code: i32,
}

#[repr(C)]
pub struct ChaCha20Poly1305EncryptResult {
    pub ciphertext: *mut c_uchar,
    pub length: usize,
    pub error_code: i32,
}

#[repr(C)]
pub struct ChaCha20Poly1305DecryptResult {
    pub plaintext: *mut c_uchar,
    pub length: usize,
    pub error_code: i32,
}

fn chacha20_poly1305_encrypt_result(result: CasResult<Vec<u8>>) -> ChaCha20Poly1305EncryptResult {
    match result {
        Ok(ciphertext) => {
            let result = ChaCha20Poly1305EncryptResult {
                ciphertext: export_bytes(&ciphertext),
                length: ciphertext.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => ChaCha20Poly1305EncryptResult {
            ciphertext: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

fn chacha20_poly1305_decrypt_result(result: CasResult<Vec<u8>>) -> ChaCha20Poly1305DecryptResult {
    match result {
        Ok(plaintext) => {
            let result = ChaCha20Poly1305DecryptResult {
                plaintext: export_bytes(&plaintext),
                length: plaintext.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => ChaCha20Poly1305DecryptResult {
            plaintext: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

#[no_mangle]
pub extern "C" fn chacha20_poly1305_key() -> ChaCha20Poly1305Key {
    let key = <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::generate_key();
    let result = ChaCha20Poly1305Key {
        key: export_bytes(&key),
        length: key.len(),
        error_code: 0,
    };
    result
}

/// Generates a random 12-byte ChaCha20-Poly1305 nonce. Use it for one message only.
#[no_mangle]
pub extern "C" fn chacha20_poly1305_nonce() -> ChaCha20Poly1305Nonce {
    let nonce = <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::generate_nonce();
    let result = ChaCha20Poly1305Nonce {
        nonce: export_bytes(&nonce),
        length: nonce.len(),
        error_code: 0,
    };
    result
}

/// Encrypts with ChaCha20-Poly1305 under a caller-supplied 12-byte nonce and
/// returns `ciphertext || tag`. The nonce must never be reused under the same
/// key; prefer `chacha20_poly1305_seal`.
#[no_mangle]
pub extern "C" fn chacha20_poly1305_encrypt(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
) -> ChaCha20Poly1305EncryptResult {
    chacha20_poly1305_encrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_encrypt = bytes_from_ffi(to_encrypt, to_encrypt_length)?;
        <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::encrypt_plaintext(key, nonce, to_encrypt)
    })())
}

/// Decrypts `ciphertext || tag` from `chacha20_poly1305_encrypt`. A tampered
/// ciphertext or the wrong key or nonce is `DecryptionFailed`.
#[no_mangle]
pub extern "C" fn chacha20_poly1305_decrypt(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
) -> ChaCha20Poly1305DecryptResult {
    chacha20_poly1305_decrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_decrypt = bytes_from_ffi(to_decrypt, to_decrypt_length)?;
        <CASChacha20Poly1305 as Chacha20Poly1305Encryption>::decrypt_ciphertext(key, nonce, to_decrypt)
    })())
}

/// Encrypts `plaintext` with ChaCha20-Poly1305 under a fresh random nonce and
/// returns `nonce || ciphertext || tag`. This is the recommended way to
/// encrypt: the caller never handles a nonce, so it cannot reuse one. Rotate
/// the key well before about 2^32 messages. `aad` may be empty (a null pointer
/// is accepted when `aad_length` is 0); the same AAD must be passed to
/// `chacha20_poly1305_open`.
#[no_mangle]
pub extern "C" fn chacha20_poly1305_seal(
    key: *const c_uchar,
    key_length: usize,
    plaintext: *const c_uchar,
    plaintext_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> ChaCha20Poly1305EncryptResult {
    chacha20_poly1305_encrypt_result((|| {
        let key = bytes_from_ffi(key, key_length)?;
        let plaintext = bytes_from_ffi(plaintext, plaintext_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASChacha20Poly1305 as CASAeadSeal>::seal(key, plaintext, Some(aad))
    })())
}

/// Decrypts a `nonce || ciphertext || tag` blob produced by
/// `chacha20_poly1305_seal`. A blob shorter than nonce + tag is `InvalidInput`;
/// a tampered blob or the wrong AAD is `DecryptionFailed`.
#[no_mangle]
pub extern "C" fn chacha20_poly1305_open(
    key: *const c_uchar,
    key_length: usize,
    sealed: *const c_uchar,
    sealed_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> ChaCha20Poly1305DecryptResult {
    chacha20_poly1305_decrypt_result((|| {
        let key = bytes_from_ffi(key, key_length)?;
        let sealed = bytes_from_ffi(sealed, sealed_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASChacha20Poly1305 as CASAeadSeal>::open(key, sealed, Some(aad))
    })())
}

/// `chacha20_poly1305_encrypt` with additional authenticated data. Returns
/// `ciphertext || tag`. The caller supplies the nonce and must never reuse it
/// under the same key; prefer `chacha20_poly1305_seal`.
#[no_mangle]
pub extern "C" fn chacha20_poly1305_encrypt_with_aad(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> ChaCha20Poly1305EncryptResult {
    chacha20_poly1305_encrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_encrypt = bytes_from_ffi(to_encrypt, to_encrypt_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASChacha20Poly1305 as Chacha20Poly1305AadEncryption>::encrypt_plaintext_with_aad(key, nonce, to_encrypt, aad)
    })())
}

/// `chacha20_poly1305_decrypt` with additional authenticated data. The wrong
/// AAD is `DecryptionFailed`.
#[no_mangle]
pub extern "C" fn chacha20_poly1305_decrypt_with_aad(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> ChaCha20Poly1305DecryptResult {
    chacha20_poly1305_decrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_decrypt = bytes_from_ffi(to_decrypt, to_decrypt_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASChacha20Poly1305 as Chacha20Poly1305AadEncryption>::decrypt_ciphertext_with_aad(key, nonce, to_decrypt, aad)
    })())
}

#[cfg(test)]
fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn chacha20_poly1305_seal_open_test() {
    use cas_lib::error::CasError;
    let key = chacha20_poly1305_key();
    let key = take_bytes(key.key, key.length);
    assert_eq!(32, key.len());
    let nonce_len = CASChacha20Poly1305::NONCE_LEN;
    let plaintext = b"WelcomeHome".to_vec();
    let aad = b"header".to_vec();
    let do_open = |key: &[u8], sealed: &[u8], aad: &[u8]| chacha20_poly1305_open(key.as_ptr(), key.len(), sealed.as_ptr(), sealed.len(), aad.as_ptr(), aad.len());

    let sealed = chacha20_poly1305_seal(key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_eq!(0, sealed.error_code);
    let sealed = take_bytes(sealed.ciphertext, sealed.length);
    assert_eq!(nonce_len + plaintext.len() + 16, sealed.len());

    // Round trip.
    let opened = do_open(&key, &sealed, &aad);
    assert_eq!(0, opened.error_code);
    assert_eq!(plaintext, take_bytes(opened.plaintext, opened.length));

    // Wrong or missing AAD.
    for wrong_aad in [&b"other header"[..], &[][..]] {
        let opened = do_open(&key, &sealed, wrong_aad);
        assert!(opened.plaintext.is_null());
        assert_eq!(cas_error_code(&CasError::DecryptionFailed), opened.error_code);
    }

    // A flipped bit in the nonce, the ciphertext or the tag.
    for index in [0, nonce_len, sealed.len() - 1] {
        let mut tampered = sealed.clone();
        tampered[index] ^= 0x01;
        let opened = do_open(&key, &tampered, &aad);
        assert!(opened.plaintext.is_null());
        assert_eq!(cas_error_code(&CasError::DecryptionFailed), opened.error_code);
    }

    // A different key.
    let wrong_key = chacha20_poly1305_key();
    let wrong_key = take_bytes(wrong_key.key, wrong_key.length);
    assert_eq!(cas_error_code(&CasError::DecryptionFailed), do_open(&wrong_key, &sealed, &aad).error_code);

    // Too short to hold a nonce and a tag.
    let opened = do_open(&key, &sealed[..nonce_len + 15], &aad);
    assert_eq!(cas_error_code(&CasError::InvalidInput), opened.error_code);

    // A fresh nonce per call.
    let sealed_again = chacha20_poly1305_seal(key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_ne!(sealed, take_bytes(sealed_again.ciphertext, sealed_again.length));

    // The blob is `nonce || ciphertext || tag`, so the caller-nonce API opens it.
    let (nonce, ciphertext) = sealed.split_at(nonce_len);
    let decrypted = chacha20_poly1305_decrypt_with_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), ciphertext.as_ptr(), ciphertext.len(), aad.as_ptr(), aad.len());
    assert_eq!(0, decrypted.error_code);
    assert_eq!(plaintext, take_bytes(decrypted.plaintext, decrypted.length));

    // Empty AAD may be passed as a null pointer.
    let sealed = chacha20_poly1305_seal(key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), std::ptr::null(), 0);
    let sealed = take_bytes(sealed.ciphertext, sealed.length);
    let opened = chacha20_poly1305_open(key.as_ptr(), key.len(), sealed.as_ptr(), sealed.len(), std::ptr::null(), 0);
    assert_eq!(plaintext, take_bytes(opened.plaintext, opened.length));

    // A null pointer with a non-zero length is reported, not a panic.
    let sealed = chacha20_poly1305_seal(key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), std::ptr::null(), 4);
    assert!(sealed.ciphertext.is_null());
    assert_eq!(cas_error_code(&CasError::InvalidInput), sealed.error_code);

    // Wrong key length.
    let short_key = vec![0u8; 5];
    let sealed = chacha20_poly1305_seal(short_key.as_ptr(), short_key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_eq!(cas_error_code(&CasError::InvalidKey), sealed.error_code);
    let opened = do_open(&short_key, &vec![0u8; nonce_len + 16], &aad);
    assert_eq!(cas_error_code(&CasError::InvalidKey), opened.error_code);
}

#[test]
fn chacha20_poly1305_encrypt_decrypt_test() {
    use cas_lib::error::CasError;
    let key = chacha20_poly1305_key();
    let key = take_bytes(key.key, key.length);
    let nonce = chacha20_poly1305_nonce();
    let nonce = take_bytes(nonce.nonce, nonce.length);
    assert_eq!(12, nonce.len());
    let plaintext = b"WelcomeHome".to_vec();
    let aad = b"record-42".to_vec();

    // Round trip without AAD.
    let encrypted = chacha20_poly1305_encrypt(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len());
    assert_eq!(0, encrypted.error_code);
    let ciphertext = take_bytes(encrypted.ciphertext, encrypted.length);
    assert_eq!(plaintext.len() + 16, ciphertext.len());
    let decrypted = chacha20_poly1305_decrypt(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), ciphertext.as_ptr(), ciphertext.len());
    assert_eq!(0, decrypted.error_code);
    assert_eq!(plaintext, take_bytes(decrypted.plaintext, decrypted.length));

    // Empty AAD gives the same output as the non-AAD API.
    let encrypted = chacha20_poly1305_encrypt_with_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), std::ptr::null(), 0);
    assert_eq!(ciphertext, take_bytes(encrypted.ciphertext, encrypted.length));

    // Round trip with AAD.
    let do_decrypt = |nonce: &[u8], key: &[u8], ciphertext: &[u8], aad: &[u8]| chacha20_poly1305_decrypt_with_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), ciphertext.as_ptr(), ciphertext.len(), aad.as_ptr(), aad.len());
    let encrypted = chacha20_poly1305_encrypt_with_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_eq!(0, encrypted.error_code);
    let ciphertext = take_bytes(encrypted.ciphertext, encrypted.length);
    let decrypted = do_decrypt(&nonce, &key, &ciphertext, &aad);
    assert_eq!(0, decrypted.error_code);
    assert_eq!(plaintext, take_bytes(decrypted.plaintext, decrypted.length));

    // Wrong or missing AAD.
    for wrong_aad in [&b"record-43"[..], &[][..]] {
        let decrypted = do_decrypt(&nonce, &key, &ciphertext, wrong_aad);
        assert!(decrypted.plaintext.is_null());
        assert_eq!(cas_error_code(&CasError::DecryptionFailed), decrypted.error_code);
    }

    // The non-AAD decrypt does not accept a ciphertext bound to AAD.
    let decrypted = chacha20_poly1305_decrypt(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), ciphertext.as_ptr(), ciphertext.len());
    assert_eq!(cas_error_code(&CasError::DecryptionFailed), decrypted.error_code);

    // A flipped bit in the ciphertext or the tag.
    for index in [0, ciphertext.len() - 1] {
        let mut tampered = ciphertext.clone();
        tampered[index] ^= 0x01;
        let decrypted = do_decrypt(&nonce, &key, &tampered, &aad);
        assert!(decrypted.plaintext.is_null());
        assert_eq!(cas_error_code(&CasError::DecryptionFailed), decrypted.error_code);
    }

    // A different nonce or key.
    let mut wrong_nonce = nonce.clone();
    wrong_nonce[0] ^= 0x01;
    assert_eq!(cas_error_code(&CasError::DecryptionFailed), do_decrypt(&wrong_nonce, &key, &ciphertext, &aad).error_code);
    let wrong_key = chacha20_poly1305_key();
    let wrong_key = take_bytes(wrong_key.key, wrong_key.length);
    assert_eq!(cas_error_code(&CasError::DecryptionFailed), do_decrypt(&nonce, &wrong_key, &ciphertext, &aad).error_code);

    // Wrong nonce or key length.
    let short = vec![0u8; 5];
    let encrypted = chacha20_poly1305_encrypt_with_aad(short.as_ptr(), short.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_eq!(cas_error_code(&CasError::InvalidNonce), encrypted.error_code);
    let encrypted = chacha20_poly1305_encrypt(short.as_ptr(), short.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len());
    assert_eq!(cas_error_code(&CasError::InvalidNonce), encrypted.error_code);
    let encrypted = chacha20_poly1305_encrypt_with_aad(nonce.as_ptr(), nonce.len(), short.as_ptr(), short.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_eq!(cas_error_code(&CasError::InvalidKey), encrypted.error_code);
    let decrypted = chacha20_poly1305_decrypt(nonce.as_ptr(), nonce.len(), short.as_ptr(), short.len(), ciphertext.as_ptr(), ciphertext.len());
    assert_eq!(cas_error_code(&CasError::InvalidKey), decrypted.error_code);

    // A null pointer with a non-zero length is reported, not a panic.
    let encrypted = chacha20_poly1305_encrypt(std::ptr::null(), 12, key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len());
    assert!(encrypted.ciphertext.is_null());
    assert_eq!(cas_error_code(&CasError::InvalidInput), encrypted.error_code);
}

// RFC 8439 section 2.8.2: AEAD_CHACHA20_POLY1305 test vector.
#[test]
fn chacha20_poly1305_rfc_8439_test() {
    let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = hex("070000004041424344454647");
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
    let expected = hex(concat!(
        "d31a8d34648e60db7b86afbc53ef7ec2",
        "a4aded51296e08fea9e2b5a736ee62d6",
        "3dbea45e8ca9671282fafb69da92728b",
        "1a71de0a9e060b2905d6a5b67ecd3b36",
        "92ddbd7f2d778b8c9803aee328091b58",
        "fab324e4fad675945585808b4831d7bc",
        "3ff4def08e4b7a9de576d26586cec64b",
        "6116",
        "1ae10b594f09e26a7e902ecbd0600691",
    ));

    let encrypted = chacha20_poly1305_encrypt_with_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_eq!(0, encrypted.error_code);
    assert_eq!(expected, take_bytes(encrypted.ciphertext, encrypted.length));

    let decrypted = chacha20_poly1305_decrypt_with_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), expected.as_ptr(), expected.len(), aad.as_ptr(), aad.len());
    assert_eq!(0, decrypted.error_code);
    assert_eq!(plaintext, take_bytes(decrypted.plaintext, decrypted.length));

    // The same vector, framed as a sealed blob.
    let sealed = [nonce.clone(), expected].concat();
    let opened = chacha20_poly1305_open(key.as_ptr(), key.len(), sealed.as_ptr(), sealed.len(), aad.as_ptr(), aad.len());
    assert_eq!(0, opened.error_code);
    assert_eq!(plaintext, take_bytes(opened.plaintext, opened.length));
}
