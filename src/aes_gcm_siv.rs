use cas_lib::error::CasResult;
use cas_lib::symmetric::aes_gcm_siv::{CASAES128SIV, CASAES256SIV};
use cas_lib::symmetric::cas_symmetric_encryption::{CASAES128SIVAadEncryption, CASAES128SIVEncryption, CASAES256SIVAadEncryption, CASAES256SIVEncryption, CASAeadSeal};
use std::ffi::c_uchar;

use crate::helpers::{bytes_from_ffi, cas_error_code, export_bytes};
#[cfg(test)]
use crate::helpers::take_bytes;

#[repr(C)]
pub struct AesGcmSivNonce {
    pub nonce: *mut c_uchar,
    pub length: usize,
    /// `0` on success. Generation takes no caller input.
    pub error_code: i32,
}

#[repr(C)]
pub struct AesGcmSivKey {
    pub key: *mut c_uchar,
    pub length: usize,
    /// `0` on success. Generation takes no caller input.
    pub error_code: i32,
}

#[repr(C)]
pub struct AesGcmSivEncryptResult {
    pub ciphertext: *mut c_uchar,
    pub length: usize,
    pub error_code: i32,
}

#[repr(C)]
pub struct AesGcmSivDecryptResult {
    pub plaintext: *mut c_uchar,
    pub length: usize,
    pub error_code: i32,
}

fn aes_gcm_siv_encrypt_result(result: CasResult<Vec<u8>>) -> AesGcmSivEncryptResult {
    match result {
        Ok(ciphertext) => {
            let result = AesGcmSivEncryptResult {
                ciphertext: export_bytes(&ciphertext),
                length: ciphertext.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => AesGcmSivEncryptResult {
            ciphertext: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

fn aes_gcm_siv_decrypt_result(result: CasResult<Vec<u8>>) -> AesGcmSivDecryptResult {
    match result {
        Ok(plaintext) => {
            let result = AesGcmSivDecryptResult {
                plaintext: export_bytes(&plaintext),
                length: plaintext.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => AesGcmSivDecryptResult {
            plaintext: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

/// Generates a random 12-byte nonce for AES-128-GCM-SIV and AES-256-GCM-SIV.
#[no_mangle]
pub extern "C" fn aes_gcm_siv_nonce() -> AesGcmSivNonce {
    let random_bytes = <CASAES256SIV as CASAES256SIVEncryption>::generate_nonce();
    let result = AesGcmSivNonce {
        nonce: export_bytes(&random_bytes),
        length: random_bytes.len(),
        error_code: 0,
    };
    result
}

#[no_mangle]
pub extern "C" fn aes_128_gcm_siv_key() -> AesGcmSivKey {
    let key = <CASAES128SIV as CASAES128SIVEncryption>::generate_key();
    let result = AesGcmSivKey {
        key: export_bytes(&key),
        length: key.len(),
        error_code: 0,
    };
    result
}

#[no_mangle]
pub extern "C" fn aes_256_gcm_siv_key() -> AesGcmSivKey {
    let key = <CASAES256SIV as CASAES256SIVEncryption>::generate_key();
    let result = AesGcmSivKey {
        key: export_bytes(&key),
        length: key.len(),
        error_code: 0,
    };
    result
}

/// Encrypts with AES-128-GCM-SIV under a caller-supplied 12-byte nonce and
/// returns `ciphertext || tag`. AES-GCM-SIV is nonce-misuse resistant: reusing
/// a nonce under the same key only reveals whether two messages were identical,
/// but it still reveals that, so prefer `aes_128_gcm_siv_seal`.
#[no_mangle]
pub extern "C" fn aes_128_gcm_siv_encrypt_bytes_with_key(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
) -> AesGcmSivEncryptResult {
    aes_gcm_siv_encrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_encrypt = bytes_from_ffi(to_encrypt, to_encrypt_length)?;
        <CASAES128SIV as CASAES128SIVEncryption>::encrypt_plaintext(key, nonce, to_encrypt)
    })())
}

/// Decrypts `ciphertext || tag` from `aes_128_gcm_siv_encrypt_bytes_with_key`.
/// A tampered ciphertext or the wrong key or nonce is `DecryptionFailed`.
#[no_mangle]
pub extern "C" fn aes_128_gcm_siv_decrypt_bytes_with_key(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
) -> AesGcmSivDecryptResult {
    aes_gcm_siv_decrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_decrypt = bytes_from_ffi(to_decrypt, to_decrypt_length)?;
        <CASAES128SIV as CASAES128SIVEncryption>::decrypt_ciphertext(key, nonce, to_decrypt)
    })())
}

/// AES-256-GCM-SIV version of `aes_128_gcm_siv_encrypt_bytes_with_key`.
#[no_mangle]
pub extern "C" fn aes_256_gcm_siv_encrypt_bytes_with_key(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
) -> AesGcmSivEncryptResult {
    aes_gcm_siv_encrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_encrypt = bytes_from_ffi(to_encrypt, to_encrypt_length)?;
        <CASAES256SIV as CASAES256SIVEncryption>::encrypt_plaintext(key, nonce, to_encrypt)
    })())
}

/// AES-256-GCM-SIV version of `aes_128_gcm_siv_decrypt_bytes_with_key`.
#[no_mangle]
pub extern "C" fn aes_256_gcm_siv_decrypt_bytes_with_key(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
) -> AesGcmSivDecryptResult {
    aes_gcm_siv_decrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_decrypt = bytes_from_ffi(to_decrypt, to_decrypt_length)?;
        <CASAES256SIV as CASAES256SIVEncryption>::decrypt_ciphertext(key, nonce, to_decrypt)
    })())
}

/// Encrypts `plaintext` with AES-128-GCM-SIV under a fresh random nonce and
/// returns `nonce || ciphertext || tag`. This is the recommended way to
/// encrypt: the caller never handles a nonce. Rotate the key well before about
/// 2^32 messages. `aad` may be empty (a null pointer is accepted when
/// `aad_length` is 0); the same AAD must be passed to `aes_128_gcm_siv_open`.
#[no_mangle]
pub extern "C" fn aes_128_gcm_siv_seal(
    key: *const c_uchar,
    key_length: usize,
    plaintext: *const c_uchar,
    plaintext_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesGcmSivEncryptResult {
    aes_gcm_siv_encrypt_result((|| {
        let key = bytes_from_ffi(key, key_length)?;
        let plaintext = bytes_from_ffi(plaintext, plaintext_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES128SIV as CASAeadSeal>::seal(key, plaintext, Some(aad))
    })())
}

/// Decrypts a `nonce || ciphertext || tag` blob produced by
/// `aes_128_gcm_siv_seal`. A blob shorter than nonce + tag is `InvalidInput`;
/// a tampered blob or the wrong AAD is `DecryptionFailed`.
#[no_mangle]
pub extern "C" fn aes_128_gcm_siv_open(
    key: *const c_uchar,
    key_length: usize,
    sealed: *const c_uchar,
    sealed_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesGcmSivDecryptResult {
    aes_gcm_siv_decrypt_result((|| {
        let key = bytes_from_ffi(key, key_length)?;
        let sealed = bytes_from_ffi(sealed, sealed_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES128SIV as CASAeadSeal>::open(key, sealed, Some(aad))
    })())
}

/// AES-256-GCM-SIV version of `aes_128_gcm_siv_seal`.
#[no_mangle]
pub extern "C" fn aes_256_gcm_siv_seal(
    key: *const c_uchar,
    key_length: usize,
    plaintext: *const c_uchar,
    plaintext_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesGcmSivEncryptResult {
    aes_gcm_siv_encrypt_result((|| {
        let key = bytes_from_ffi(key, key_length)?;
        let plaintext = bytes_from_ffi(plaintext, plaintext_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES256SIV as CASAeadSeal>::seal(key, plaintext, Some(aad))
    })())
}

/// AES-256-GCM-SIV version of `aes_128_gcm_siv_open`.
#[no_mangle]
pub extern "C" fn aes_256_gcm_siv_open(
    key: *const c_uchar,
    key_length: usize,
    sealed: *const c_uchar,
    sealed_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesGcmSivDecryptResult {
    aes_gcm_siv_decrypt_result((|| {
        let key = bytes_from_ffi(key, key_length)?;
        let sealed = bytes_from_ffi(sealed, sealed_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES256SIV as CASAeadSeal>::open(key, sealed, Some(aad))
    })())
}

/// `aes_128_gcm_siv_encrypt_bytes_with_key` with additional authenticated
/// data. Returns `ciphertext || tag`. The caller supplies the nonce; prefer
/// `aes_128_gcm_siv_seal`.
#[no_mangle]
pub extern "C" fn aes_128_gcm_siv_encrypt_bytes_with_aad(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesGcmSivEncryptResult {
    aes_gcm_siv_encrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_encrypt = bytes_from_ffi(to_encrypt, to_encrypt_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES128SIV as CASAES128SIVAadEncryption>::encrypt_plaintext_with_aad(key, nonce, to_encrypt, aad)
    })())
}

/// `aes_128_gcm_siv_decrypt_bytes_with_key` with additional authenticated
/// data. The wrong AAD is `DecryptionFailed`.
#[no_mangle]
pub extern "C" fn aes_128_gcm_siv_decrypt_bytes_with_aad(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesGcmSivDecryptResult {
    aes_gcm_siv_decrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_decrypt = bytes_from_ffi(to_decrypt, to_decrypt_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES128SIV as CASAES128SIVAadEncryption>::decrypt_ciphertext_with_aad(key, nonce, to_decrypt, aad)
    })())
}

/// AES-256-GCM-SIV version of `aes_128_gcm_siv_encrypt_bytes_with_aad`.
#[no_mangle]
pub extern "C" fn aes_256_gcm_siv_encrypt_bytes_with_aad(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesGcmSivEncryptResult {
    aes_gcm_siv_encrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_encrypt = bytes_from_ffi(to_encrypt, to_encrypt_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES256SIV as CASAES256SIVAadEncryption>::encrypt_plaintext_with_aad(key, nonce, to_encrypt, aad)
    })())
}

/// AES-256-GCM-SIV version of `aes_128_gcm_siv_decrypt_bytes_with_aad`.
#[no_mangle]
pub extern "C" fn aes_256_gcm_siv_decrypt_bytes_with_aad(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> AesGcmSivDecryptResult {
    aes_gcm_siv_decrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_decrypt = bytes_from_ffi(to_decrypt, to_decrypt_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <CASAES256SIV as CASAES256SIVAadEncryption>::decrypt_ciphertext_with_aad(key, nonce, to_decrypt, aad)
    })())
}

#[cfg(test)]
type AesGcmSivKeyFn = extern "C" fn() -> AesGcmSivKey;
#[cfg(test)]
type AesGcmSivEncryptFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize) -> AesGcmSivEncryptResult;
#[cfg(test)]
type AesGcmSivDecryptFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize) -> AesGcmSivDecryptResult;
#[cfg(test)]
type AesGcmSivSealFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize) -> AesGcmSivEncryptResult;
#[cfg(test)]
type AesGcmSivOpenFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize) -> AesGcmSivDecryptResult;
#[cfg(test)]
type AesGcmSivEncryptAadFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize) -> AesGcmSivEncryptResult;
#[cfg(test)]
type AesGcmSivDecryptAadFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize, *const c_uchar, usize) -> AesGcmSivDecryptResult;

#[cfg(test)]
fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

// Runs the caller-nonce checks (with and without AAD) against one key size.
#[cfg(test)]
fn check_aes_gcm_siv_encrypt_decrypt(key_fn: AesGcmSivKeyFn, key_len: usize, encrypt: AesGcmSivEncryptFn, decrypt: AesGcmSivDecryptFn, encrypt_aad: AesGcmSivEncryptAadFn, decrypt_aad: AesGcmSivDecryptAadFn) {
    use cas_lib::error::CasError;
    let key = key_fn();
    let key = take_bytes(key.key, key.length);
    assert_eq!(key_len, key.len());
    let nonce = aes_gcm_siv_nonce();
    let nonce = take_bytes(nonce.nonce, nonce.length);
    assert_eq!(12, nonce.len());
    let plaintext = b"WelcomeHome".to_vec();
    let aad = b"record-42".to_vec();

    // Round trip without AAD.
    let encrypted = encrypt(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len());
    assert_eq!(0, encrypted.error_code);
    let ciphertext = take_bytes(encrypted.ciphertext, encrypted.length);
    assert_eq!(plaintext.len() + 16, ciphertext.len());
    let decrypted = decrypt(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), ciphertext.as_ptr(), ciphertext.len());
    assert_eq!(0, decrypted.error_code);
    assert_eq!(plaintext, take_bytes(decrypted.plaintext, decrypted.length));

    // Empty AAD gives the same output as the non-AAD API.
    let encrypted = encrypt_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), std::ptr::null(), 0);
    assert_eq!(ciphertext, take_bytes(encrypted.ciphertext, encrypted.length));

    // Round trip with AAD.
    let do_decrypt = |nonce: &[u8], key: &[u8], ciphertext: &[u8], aad: &[u8]| decrypt_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), ciphertext.as_ptr(), ciphertext.len(), aad.as_ptr(), aad.len());
    let encrypted = encrypt_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
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
    let decrypted = decrypt(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), ciphertext.as_ptr(), ciphertext.len());
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
    let wrong_key = key_fn();
    let wrong_key = take_bytes(wrong_key.key, wrong_key.length);
    assert_eq!(cas_error_code(&CasError::DecryptionFailed), do_decrypt(&nonce, &wrong_key, &ciphertext, &aad).error_code);

    // Wrong nonce or key length.
    let short = vec![0u8; 5];
    let encrypted = encrypt_aad(short.as_ptr(), short.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_eq!(cas_error_code(&CasError::InvalidNonce), encrypted.error_code);
    let encrypted = encrypt(short.as_ptr(), short.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len());
    assert_eq!(cas_error_code(&CasError::InvalidNonce), encrypted.error_code);
    let encrypted = encrypt_aad(nonce.as_ptr(), nonce.len(), short.as_ptr(), short.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_eq!(cas_error_code(&CasError::InvalidKey), encrypted.error_code);
    let decrypted = decrypt(nonce.as_ptr(), nonce.len(), short.as_ptr(), short.len(), ciphertext.as_ptr(), ciphertext.len());
    assert_eq!(cas_error_code(&CasError::InvalidKey), decrypted.error_code);

    // A null pointer with a non-zero length is reported, not a panic.
    let encrypted = encrypt(std::ptr::null(), 12, key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len());
    assert!(encrypted.ciphertext.is_null());
    assert_eq!(cas_error_code(&CasError::InvalidInput), encrypted.error_code);
}

// Runs the seal/open checks against one key size.
#[cfg(test)]
fn check_aes_gcm_siv_seal_open(key_fn: AesGcmSivKeyFn, seal: AesGcmSivSealFn, open: AesGcmSivOpenFn, decrypt_aad: AesGcmSivDecryptAadFn) {
    use cas_lib::error::CasError;
    let key = key_fn();
    let key = take_bytes(key.key, key.length);
    let nonce_len = CASAES256SIV::NONCE_LEN;
    let plaintext = b"WelcomeHome".to_vec();
    let aad = b"header".to_vec();
    let do_open = |key: &[u8], sealed: &[u8], aad: &[u8]| open(key.as_ptr(), key.len(), sealed.as_ptr(), sealed.len(), aad.as_ptr(), aad.len());

    let sealed = seal(key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
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
    let wrong_key = key_fn();
    let wrong_key = take_bytes(wrong_key.key, wrong_key.length);
    assert_eq!(cas_error_code(&CasError::DecryptionFailed), do_open(&wrong_key, &sealed, &aad).error_code);

    // Too short to hold a nonce and a tag.
    let opened = do_open(&key, &sealed[..nonce_len + 15], &aad);
    assert_eq!(cas_error_code(&CasError::InvalidInput), opened.error_code);

    // A fresh nonce per call.
    let sealed_again = seal(key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_ne!(sealed, take_bytes(sealed_again.ciphertext, sealed_again.length));

    // The blob is `nonce || ciphertext || tag`, so the caller-nonce API opens it.
    let (nonce, ciphertext) = sealed.split_at(nonce_len);
    let decrypted = decrypt_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), ciphertext.as_ptr(), ciphertext.len(), aad.as_ptr(), aad.len());
    assert_eq!(0, decrypted.error_code);
    assert_eq!(plaintext, take_bytes(decrypted.plaintext, decrypted.length));

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
    let opened = do_open(&short_key, &vec![0u8; nonce_len + 16], &aad);
    assert_eq!(cas_error_code(&CasError::InvalidKey), opened.error_code);
}

#[test]
fn aes_128_gcm_siv_encrypt_decrypt_test() {
    check_aes_gcm_siv_encrypt_decrypt(aes_128_gcm_siv_key, 16, aes_128_gcm_siv_encrypt_bytes_with_key, aes_128_gcm_siv_decrypt_bytes_with_key, aes_128_gcm_siv_encrypt_bytes_with_aad, aes_128_gcm_siv_decrypt_bytes_with_aad);
}

#[test]
fn aes_256_gcm_siv_encrypt_decrypt_test() {
    check_aes_gcm_siv_encrypt_decrypt(aes_256_gcm_siv_key, 32, aes_256_gcm_siv_encrypt_bytes_with_key, aes_256_gcm_siv_decrypt_bytes_with_key, aes_256_gcm_siv_encrypt_bytes_with_aad, aes_256_gcm_siv_decrypt_bytes_with_aad);
}

#[test]
fn aes_128_gcm_siv_seal_open_test() {
    check_aes_gcm_siv_seal_open(aes_128_gcm_siv_key, aes_128_gcm_siv_seal, aes_128_gcm_siv_open, aes_128_gcm_siv_decrypt_bytes_with_aad);
}

#[test]
fn aes_256_gcm_siv_seal_open_test() {
    check_aes_gcm_siv_seal_open(aes_256_gcm_siv_key, aes_256_gcm_siv_seal, aes_256_gcm_siv_open, aes_256_gcm_siv_decrypt_bytes_with_aad);
}

// RFC 8452 Appendix C: (key, nonce, plaintext, aad, ciphertext || tag).
#[cfg(test)]
fn check_aes_gcm_siv_vectors(vectors: &[(&str, &str, &str, &str, &str)], encrypt_aad: AesGcmSivEncryptAadFn, decrypt_aad: AesGcmSivDecryptAadFn) {
    for (key, nonce, plaintext, aad, expected) in vectors {
        let (key, nonce, plaintext, aad, expected) = (hex(key), hex(nonce), hex(plaintext), hex(aad), hex(expected));
        let encrypted = encrypt_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
        assert_eq!(0, encrypted.error_code);
        assert_eq!(expected, take_bytes(encrypted.ciphertext, encrypted.length));
        let decrypted = decrypt_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), expected.as_ptr(), expected.len(), aad.as_ptr(), aad.len());
        assert_eq!(0, decrypted.error_code);
        assert_eq!(plaintext, take_bytes(decrypted.plaintext, decrypted.length));
    }
}

#[test]
fn aes_128_gcm_siv_rfc_8452_test() {
    check_aes_gcm_siv_vectors(&[
        ("01000000000000000000000000000000", "030000000000000000000000", "", "", "dc20e2d83f25705bb49e439eca56de25"),
        ("01000000000000000000000000000000", "030000000000000000000000", "0100000000000000", "", "b5d839330ac7b786578782fff6013b815b287c22493a364c"),
        ("01000000000000000000000000000000", "030000000000000000000000", "0200000000000000", "01", "1e6daba35669f4273b0a1a2560969cdf790d99759abd1508"),
    ], aes_128_gcm_siv_encrypt_bytes_with_aad, aes_128_gcm_siv_decrypt_bytes_with_aad);
}

#[test]
fn aes_256_gcm_siv_rfc_8452_test() {
    check_aes_gcm_siv_vectors(&[
        ("0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000", "", "", "07f5f4169bbf55a8400cd47ea6fd400f"),
        ("0100000000000000000000000000000000000000000000000000000000000000", "030000000000000000000000", "0100000000000000", "", "c2ef328e5c71c83b843122130f7364b761e0b97427e3df28"),
    ], aes_256_gcm_siv_encrypt_bytes_with_aad, aes_256_gcm_siv_decrypt_bytes_with_aad);
}
