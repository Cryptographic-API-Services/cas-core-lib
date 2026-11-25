use std::ffi::{c_char, c_uchar, CString};

use cas_lib::asymmetric::types::CASRSAEncryption;
use cas_lib::asymmetric::cas_rsa::CASRSA;
use cas_lib::error::CasResult;

mod types;
use self::types::{RsaKeyPair, RsaSignBytesResults};
use crate::helpers::{bytes_from_ffi, cas_error_code, export_bytes, string_from_c_str, CasVerifyResult};

#[no_mangle]
pub extern "C" fn get_key_pair(key_size: usize) -> RsaKeyPair {
    match <CASRSA as CASRSAEncryption>::generate_rsa_keys(key_size) {
        Ok(key_pair) => RsaKeyPair {
            priv_key: match CString::new(key_pair.private_key) {
                Ok(value) => value.into_raw(),
                Err(_) => return RsaKeyPair { priv_key: std::ptr::null_mut(), pub_key: std::ptr::null_mut(), error_code: cas_error_code(&cas_lib::error::CasError::KeyGenerationFailed) },
            },
            pub_key: match CString::new(key_pair.public_key) {
                Ok(value) => value.into_raw(),
                Err(_) => return RsaKeyPair { priv_key: std::ptr::null_mut(), pub_key: std::ptr::null_mut(), error_code: cas_error_code(&cas_lib::error::CasError::KeyGenerationFailed) },
            },
            error_code: 0,
        },
        Err(e) => RsaKeyPair {
            priv_key: std::ptr::null_mut(),
            pub_key: std::ptr::null_mut(),
            error_code: cas_error_code(&e),
        },
    }
}

/// Signs `data_to_sign` (the message itself, any length) with RSASSA-PKCS1-v1_5
/// and SHA-256 (JWS `RS256`). cas-lib hashes the message and adds the standard
/// DigestInfo prefix, so the signature verifies with OpenSSL, .NET
/// `RSA.VerifyData(..., SHA256, Pkcs1)` and other RS256 verifiers.
#[no_mangle]
pub extern "C" fn rsa_sign_with_key_bytes(
    private_key: *const c_char,
    data_to_sign: *const c_uchar,
    data_to_sign_length: usize,
) -> RsaSignBytesResults {
    rsa_sign(private_key, data_to_sign, data_to_sign_length, <CASRSA as CASRSAEncryption>::sign)
}

/// Verifies an RS256 `signature` over `data_to_verify` (the message itself).
#[no_mangle]
pub extern "C" fn rsa_verify_bytes(
    public_key: *const c_char,
    data_to_verify: *const c_uchar,
    data_to_verify_length: usize,
    signature: *const c_uchar,
    signature_length: usize,
) -> CasVerifyResult {
    rsa_verify(public_key, data_to_verify, data_to_verify_length, signature, signature_length, <CASRSA as CASRSAEncryption>::verify)
}

/// Signs `data_to_sign` (the message itself, any length) with RSASSA-PSS,
/// SHA-256, MGF1-SHA-256 and a 32-byte random salt (JWS `PS256`). Recommended
/// over [`rsa_sign_with_key_bytes`] for new designs. Signatures are randomized.
#[no_mangle]
pub extern "C" fn rsa_sign_pss_with_key_bytes(
    private_key: *const c_char,
    data_to_sign: *const c_uchar,
    data_to_sign_length: usize,
) -> RsaSignBytesResults {
    rsa_sign(private_key, data_to_sign, data_to_sign_length, <CASRSA as CASRSAEncryption>::sign_pss)
}

/// Verifies a PS256 `signature` (MGF1-SHA-256, 32-byte salt) over
/// `data_to_verify` (the message itself).
#[no_mangle]
pub extern "C" fn rsa_verify_pss_bytes(
    public_key: *const c_char,
    data_to_verify: *const c_uchar,
    data_to_verify_length: usize,
    signature: *const c_uchar,
    signature_length: usize,
) -> CasVerifyResult {
    rsa_verify(public_key, data_to_verify, data_to_verify_length, signature, signature_length, <CASRSA as CASRSAEncryption>::verify_pss)
}

fn rsa_sign(
    private_key: *const c_char,
    data_to_sign: *const c_uchar,
    data_to_sign_length: usize,
    sign: fn(String, Vec<u8>) -> CasResult<Vec<u8>>,
) -> RsaSignBytesResults {
    let private_key_string = match string_from_c_str(private_key) {
        Ok(value) => value,
        Err(e) => return RsaSignBytesResults { signature_raw_ptr: std::ptr::null_mut(), length: 0, error_code: cas_error_code(&e) },
    };
    let data_to_sign_slice = match bytes_from_ffi(data_to_sign, data_to_sign_length) {
        Ok(value) => value,
        Err(e) => return RsaSignBytesResults { signature_raw_ptr: std::ptr::null_mut(), length: 0, error_code: cas_error_code(&e) },
    };
    match sign(private_key_string, data_to_sign_slice) {
        Ok(signed_data) => {
            let result = RsaSignBytesResults {
                signature_raw_ptr: export_bytes(&signed_data),
                length: signed_data.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => RsaSignBytesResults {
            signature_raw_ptr: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

fn rsa_verify(
    public_key: *const c_char,
    data_to_verify: *const c_uchar,
    data_to_verify_length: usize,
    signature: *const c_uchar,
    signature_length: usize,
    verify: fn(String, Vec<u8>, Vec<u8>) -> CasResult<bool>,
) -> CasVerifyResult {
    match (|| {
        let public_key_string = string_from_c_str(public_key)?;
        let data_to_verify_slice = bytes_from_ffi(data_to_verify, data_to_verify_length)?;
        let signature_slice = bytes_from_ffi(signature, signature_length)?;
        verify(public_key_string, data_to_verify_slice, signature_slice)
    })() {
        Ok(is_valid) => CasVerifyResult { is_valid, error_code: 0 },
        Err(e) => CasVerifyResult { is_valid: false, error_code: cas_error_code(&e) },
    }
}

#[test]
fn get_key_pair_test() {
    let key_size = 4096 as usize;
    let key_pair = get_key_pair(key_size);
    assert!(!key_pair.pub_key.is_null());
    assert!(!key_pair.priv_key.is_null());
}

#[test]
fn get_key_pair_rejects_1024_bits_test() {
    let key_pair = get_key_pair(1024);
    assert!(key_pair.pub_key.is_null());
    assert!(key_pair.priv_key.is_null());
    assert_eq!(cas_error_code(&cas_lib::error::CasError::InvalidParameters), key_pair.error_code);
}

#[test]
fn rsa_sign_and_verify_2048_test() {
    let key_pair = get_key_pair(2048);
    assert_eq!(0, key_pair.error_code);
    let data = b"data to sign".to_vec();
    let signature = rsa_sign_with_key_bytes(key_pair.priv_key, data.as_ptr(), data.len());
    assert_eq!(0, signature.error_code);
    assert_eq!(256, signature.length);
    let verified = rsa_verify_bytes(key_pair.pub_key, data.as_ptr(), data.len(), signature.signature_raw_ptr, signature.length);
    assert_eq!(0, verified.error_code);
    assert!(verified.is_valid);

    // RS256 is deterministic: signing the same message again gives the same signature.
    let signature_again = rsa_sign_with_key_bytes(key_pair.priv_key, data.as_ptr(), data.len());
    let first = unsafe { std::slice::from_raw_parts(signature.signature_raw_ptr, signature.length) };
    let second = unsafe { std::slice::from_raw_parts(signature_again.signature_raw_ptr, signature_again.length) };
    assert_eq!(first, second);

    let tampered = b"data to sigm".to_vec();
    let verified = rsa_verify_bytes(key_pair.pub_key, tampered.as_ptr(), tampered.len(), signature.signature_raw_ptr, signature.length);
    assert_eq!(0, verified.error_code);
    assert!(!verified.is_valid);

    // A PKCS#1 v1.5 signature is not a PSS signature.
    let verified = rsa_verify_pss_bytes(key_pair.pub_key, data.as_ptr(), data.len(), signature.signature_raw_ptr, signature.length);
    assert!(!verified.is_valid);
    unsafe {
        drop(CString::from_raw(key_pair.priv_key));
        drop(CString::from_raw(key_pair.pub_key));
    }
}

#[test]
fn rsa_sign_and_verify_long_message_test() {
    // Messages longer than the modulus work, because the message is hashed first.
    let key_pair = get_key_pair(2048);
    let data = vec![0x5au8; 10 * 1024];
    let signature = rsa_sign_with_key_bytes(key_pair.priv_key, data.as_ptr(), data.len());
    assert_eq!(0, signature.error_code);
    let verified = rsa_verify_bytes(key_pair.pub_key, data.as_ptr(), data.len(), signature.signature_raw_ptr, signature.length);
    assert!(verified.is_valid);
    let signature = rsa_sign_pss_with_key_bytes(key_pair.priv_key, data.as_ptr(), data.len());
    assert_eq!(0, signature.error_code);
    let verified = rsa_verify_pss_bytes(key_pair.pub_key, data.as_ptr(), data.len(), signature.signature_raw_ptr, signature.length);
    assert!(verified.is_valid);
    unsafe {
        drop(CString::from_raw(key_pair.priv_key));
        drop(CString::from_raw(key_pair.pub_key));
    }
}

#[test]
fn rsa_sign_and_verify_pss_2048_test() {
    let key_pair = get_key_pair(2048);
    assert_eq!(0, key_pair.error_code);
    let data = b"data to sign".to_vec();
    let signature = rsa_sign_pss_with_key_bytes(key_pair.priv_key, data.as_ptr(), data.len());
    assert_eq!(0, signature.error_code);
    assert_eq!(256, signature.length);
    let verified = rsa_verify_pss_bytes(key_pair.pub_key, data.as_ptr(), data.len(), signature.signature_raw_ptr, signature.length);
    assert_eq!(0, verified.error_code);
    assert!(verified.is_valid);

    // PSS is randomized, and both signatures verify.
    let signature_again = rsa_sign_pss_with_key_bytes(key_pair.priv_key, data.as_ptr(), data.len());
    let first = unsafe { std::slice::from_raw_parts(signature.signature_raw_ptr, signature.length) };
    let second = unsafe { std::slice::from_raw_parts(signature_again.signature_raw_ptr, signature_again.length) };
    assert_ne!(first, second);
    let verified = rsa_verify_pss_bytes(key_pair.pub_key, data.as_ptr(), data.len(), signature_again.signature_raw_ptr, signature_again.length);
    assert!(verified.is_valid);

    let tampered = b"data to sigm".to_vec();
    let verified = rsa_verify_pss_bytes(key_pair.pub_key, tampered.as_ptr(), tampered.len(), signature.signature_raw_ptr, signature.length);
    assert_eq!(0, verified.error_code);
    assert!(!verified.is_valid);

    // A PSS signature is not an RS256 signature.
    let verified = rsa_verify_bytes(key_pair.pub_key, data.as_ptr(), data.len(), signature.signature_raw_ptr, signature.length);
    assert!(!verified.is_valid);
    unsafe {
        drop(CString::from_raw(key_pair.priv_key));
        drop(CString::from_raw(key_pair.pub_key));
    }
}

#[test]
fn rsa_bad_pem_returns_error_code_test() {
    let invalid_pem = cas_error_code(&cas_lib::error::CasError::InvalidPemKey);
    let not_a_key = CString::new("not a PEM key").unwrap();
    let data = b"data to sign".to_vec();
    let signature = [0u8; 256];
    for sign in [rsa_sign_with_key_bytes as extern "C" fn(_, _, _) -> _, rsa_sign_pss_with_key_bytes] {
        let result = sign(not_a_key.as_ptr(), data.as_ptr(), data.len());
        assert!(result.signature_raw_ptr.is_null());
        assert_eq!(invalid_pem, result.error_code);
    }
    for verify in [rsa_verify_bytes as extern "C" fn(_, _, _, _, _) -> _, rsa_verify_pss_bytes] {
        let result = verify(not_a_key.as_ptr(), data.as_ptr(), data.len(), signature.as_ptr(), signature.len());
        assert!(!result.is_valid);
        assert_eq!(invalid_pem, result.error_code);
    }
}
