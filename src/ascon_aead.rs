use std::ffi::c_uchar;
use cas_lib::error::CasResult;
use cas_lib::sponges::ascon_aead::AsconAead;
use cas_lib::sponges::cas_ascon_aead::{CASAsconAead, CASAsconAeadAad};
use cas_lib::symmetric::cas_symmetric_encryption::CASAeadSeal;

use crate::helpers::{bytes_from_ffi, cas_error_code, export_bytes};
#[cfg(test)]
use crate::helpers::take_bytes;

#[repr(C)]
pub struct Ascon128EncryptResult {
    ciphertext: *mut c_uchar,
    length: usize,
    error_code: i32,
}

#[repr(C)]
pub struct Ascon128DecryptResult {
    plaintext: *mut c_uchar,
    length: usize,
    error_code: i32,
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
    let key = <AsconAead as CASAsconAead>::generate_key();
    let result = Ascon128Key {
        key: export_bytes(&key),
        length: key.len()
    };
    result
}



#[no_mangle]
pub extern "C" fn ascon_128_nonce() -> Ascon128Nonce {
    let nonce = <AsconAead as CASAsconAead>::generate_nonce();
    let result = Ascon128Nonce {
        nonce: export_bytes(&nonce),
        length: nonce.len()
    };
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
    match <AsconAead as CASAsconAead>::encrypt(key, nonce_key, to_encrypt) {
        Ok(ciphertext) => {
            let result = Ascon128EncryptResult {
                ciphertext: export_bytes(&ciphertext),
                length: ciphertext.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => Ascon128EncryptResult {
            ciphertext: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
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
    match <AsconAead as CASAsconAead>::decrypt(key, nonce_key, to_decrypt) {
        Ok(plaintext) => {
            let result = Ascon128DecryptResult {
                plaintext: export_bytes(&plaintext),
                length: plaintext.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => Ascon128DecryptResult {
            plaintext: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

fn ascon_encrypt_result(result: CasResult<Vec<u8>>) -> Ascon128EncryptResult {
    match result {
        Ok(ciphertext) => {
            let result = Ascon128EncryptResult {
                ciphertext: export_bytes(&ciphertext),
                length: ciphertext.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => Ascon128EncryptResult {
            ciphertext: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

fn ascon_decrypt_result(result: CasResult<Vec<u8>>) -> Ascon128DecryptResult {
    match result {
        Ok(plaintext) => {
            let result = Ascon128DecryptResult {
                plaintext: export_bytes(&plaintext),
                length: plaintext.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => Ascon128DecryptResult {
            plaintext: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

/// Encrypts `plaintext` with Ascon-AEAD128 under a fresh random 16-byte nonce
/// and returns `nonce || ciphertext || tag`. This is the recommended way to
/// encrypt: the caller never handles a nonce, so it cannot reuse one. `aad` may
/// be empty (a null pointer is accepted when `aad_length` is 0); the same AAD
/// must be passed to `ascon_128_open`.
#[no_mangle]
pub extern "C" fn ascon_128_seal(
    key: *const c_uchar,
    key_length: usize,
    plaintext: *const c_uchar,
    plaintext_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> Ascon128EncryptResult {
    ascon_encrypt_result((|| {
        let key = bytes_from_ffi(key, key_length)?;
        let plaintext = bytes_from_ffi(plaintext, plaintext_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <AsconAead as CASAeadSeal>::seal(key, plaintext, Some(aad))
    })())
}

/// Decrypts a `nonce || ciphertext || tag` blob produced by `ascon_128_seal`.
/// A blob shorter than nonce + tag is `InvalidInput`; a tampered blob or the
/// wrong AAD is `DecryptionFailed`.
#[no_mangle]
pub extern "C" fn ascon_128_open(
    key: *const c_uchar,
    key_length: usize,
    sealed: *const c_uchar,
    sealed_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> Ascon128DecryptResult {
    ascon_decrypt_result((|| {
        let key = bytes_from_ffi(key, key_length)?;
        let sealed = bytes_from_ffi(sealed, sealed_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <AsconAead as CASAeadSeal>::open(key, sealed, Some(aad))
    })())
}

/// `ascon_128_encrypt` with additional authenticated data. Returns
/// `ciphertext || tag`. The caller supplies the nonce and must never reuse it
/// under the same key; prefer `ascon_128_seal`.
#[no_mangle]
pub extern "C" fn ascon_128_encrypt_with_aad(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> Ascon128EncryptResult {
    ascon_encrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_encrypt = bytes_from_ffi(to_encrypt, to_encrypt_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <AsconAead as CASAsconAeadAad>::encrypt_plaintext_with_aad(key, nonce, to_encrypt, aad)
    })())
}

/// `ascon_128_decrypt` with additional authenticated data. The wrong AAD is
/// `DecryptionFailed`.
#[no_mangle]
pub extern "C" fn ascon_128_decrypt_with_aad(
    nonce_key: *const c_uchar,
    nonce_key_length: usize,
    key: *const c_uchar,
    key_length: usize,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
    aad: *const c_uchar,
    aad_length: usize,
) -> Ascon128DecryptResult {
    ascon_decrypt_result((|| {
        let nonce = bytes_from_ffi(nonce_key, nonce_key_length)?;
        let key = bytes_from_ffi(key, key_length)?;
        let to_decrypt = bytes_from_ffi(to_decrypt, to_decrypt_length)?;
        let aad = bytes_from_ffi(aad, aad_length)?;
        <AsconAead as CASAsconAeadAad>::decrypt_ciphertext_with_aad(key, nonce, to_decrypt, aad)
    })())
}

#[test]
fn ascon_128_seal_open_test() {
    use cas_lib::error::CasError;
    let key = ascon_128_key();
    let key = take_bytes(key.key, key.length);
    let nonce_len = AsconAead::NONCE_LEN;
    let plaintext = b"WelcomeHome".to_vec();
    let aad = b"header".to_vec();
    let do_open = |sealed: &[u8], aad: &[u8]| ascon_128_open(key.as_ptr(), key.len(), sealed.as_ptr(), sealed.len(), aad.as_ptr(), aad.len());

    let sealed = ascon_128_seal(key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
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
    let sealed_again = ascon_128_seal(key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_ne!(sealed, take_bytes(sealed_again.ciphertext, sealed_again.length));

    // The blob is `nonce || ciphertext || tag`, so the caller-nonce API opens it.
    let (nonce, ciphertext) = sealed.split_at(nonce_len);
    let decrypted = ascon_128_decrypt_with_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), ciphertext.as_ptr(), ciphertext.len(), aad.as_ptr(), aad.len());
    assert_eq!(plaintext, take_bytes(decrypted.plaintext, decrypted.length));

    // Empty AAD may be passed as a null pointer.
    let sealed = ascon_128_seal(key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), std::ptr::null(), 0);
    let sealed = take_bytes(sealed.ciphertext, sealed.length);
    let opened = ascon_128_open(key.as_ptr(), key.len(), sealed.as_ptr(), sealed.len(), std::ptr::null(), 0);
    assert_eq!(plaintext, take_bytes(opened.plaintext, opened.length));

    // A null pointer with a non-zero length is reported, not a panic.
    let sealed = ascon_128_seal(key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), std::ptr::null(), 4);
    assert!(sealed.ciphertext.is_null());
    assert_eq!(cas_error_code(&CasError::InvalidInput), sealed.error_code);

    // Wrong key length.
    let short_key = vec![0u8; 5];
    let sealed = ascon_128_seal(short_key.as_ptr(), short_key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_eq!(cas_error_code(&CasError::InvalidKey), sealed.error_code);
}

#[test]
fn ascon_128_encrypt_decrypt_with_aad_test() {
    use cas_lib::error::CasError;
    let key = ascon_128_key();
    let key = take_bytes(key.key, key.length);
    let nonce = ascon_128_nonce();
    let nonce = take_bytes(nonce.nonce, nonce.length);
    let plaintext = b"WelcomeHome".to_vec();
    let aad = b"record-42".to_vec();
    let do_decrypt = |ciphertext: &[u8], aad: &[u8]| ascon_128_decrypt_with_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), ciphertext.as_ptr(), ciphertext.len(), aad.as_ptr(), aad.len());

    let encrypted = ascon_128_encrypt_with_aad(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
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
    let decrypted = ascon_128_decrypt(nonce.as_ptr(), nonce.len(), key.as_ptr(), key.len(), ciphertext.as_ptr(), ciphertext.len());
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
    let encrypted = ascon_128_encrypt_with_aad(short_nonce.as_ptr(), short_nonce.len(), key.as_ptr(), key.len(), plaintext.as_ptr(), plaintext.len(), aad.as_ptr(), aad.len());
    assert_eq!(cas_error_code(&CasError::InvalidNonce), encrypted.error_code);
}