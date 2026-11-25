use cas_lib::pqc::ml_dsa::{generate_signing_and_verification_key, sign_message, verify_signature};
use crate::pqc::types::{MlDsaKeyPairResult, MlDsaSignature};
use crate::helpers::{bytes_from_ffi, cas_error_code, export_bytes, CasVerifyResult};

#[no_mangle]
pub extern "C" fn ml_dsa_generate_signing_and_verification_key() -> MlDsaKeyPairResult {
    let key_pair: cas_lib::pqc::cas_pqc::MlDsaKeyPair = generate_signing_and_verification_key();
    let result = MlDsaKeyPairResult {
        signing_key_ptr: export_bytes(&key_pair.signing_key),
        signing_key_length: key_pair.signing_key.len(),
        verification_key_ptr: export_bytes(&key_pair.verification_key),
        verification_key_length: key_pair.verification_key.len(),
        error_code: 0,
    };
    result
}

#[no_mangle]
pub extern "C" fn ml_dsa_sign_message(
    signing_key: *const u8,
    signing_key_length: usize,
    message: *const u8,
    message_length: usize,
) -> MlDsaSignature {
    match (|| {
        let signing_key_slice = bytes_from_ffi(signing_key, signing_key_length)?;
        let message_slice = bytes_from_ffi(message, message_length)?;
        sign_message(message_slice, signing_key_slice)
    })() {
        Ok(signature) => {
            let result = MlDsaSignature {
                signature_ptr: export_bytes(&signature),
                signature_length: signature.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => MlDsaSignature {
            signature_ptr: std::ptr::null_mut(),
            signature_length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

#[no_mangle]
pub extern "C" fn ml_dsa_verify_signature(
    verification_key: *const u8,
    verification_key_length: usize,
    signature: *const u8,
    signature_length: usize,
    message: *const u8,
    message_length: usize,
) -> CasVerifyResult {
    match (|| {
        let verification_key_slice = bytes_from_ffi(verification_key, verification_key_length)?;
        let signature_slice = bytes_from_ffi(signature, signature_length)?;
        let message_slice = bytes_from_ffi(message, message_length)?;
        verify_signature(message_slice, signature_slice, verification_key_slice)
    })() {
        Ok(is_valid) => CasVerifyResult { is_valid, error_code: 0 },
        Err(e) => CasVerifyResult { is_valid: false, error_code: cas_error_code(&e) },
    }
}

#[test]
fn ml_dsa_sign_and_verify_test() {
    let key_pair = ml_dsa_generate_signing_and_verification_key();
    let message = b"ML-DSA round trip".to_vec();
    let signature = ml_dsa_sign_message(
        key_pair.signing_key_ptr,
        key_pair.signing_key_length,
        message.as_ptr(),
        message.len(),
    );
    assert_eq!(0, signature.error_code);
    let result = ml_dsa_verify_signature(
        key_pair.verification_key_ptr,
        key_pair.verification_key_length,
        signature.signature_ptr,
        signature.signature_length,
        message.as_ptr(),
        message.len(),
    );
    assert_eq!(0, result.error_code);
    assert!(result.is_valid);
}

#[test]
fn ml_dsa_verify_tampered_message_test() {
    let key_pair = ml_dsa_generate_signing_and_verification_key();
    let message = b"original".to_vec();
    let tampered = b"tampered".to_vec();
    let signature = ml_dsa_sign_message(
        key_pair.signing_key_ptr,
        key_pair.signing_key_length,
        message.as_ptr(),
        message.len(),
    );
    let result = ml_dsa_verify_signature(
        key_pair.verification_key_ptr,
        key_pair.verification_key_length,
        signature.signature_ptr,
        signature.signature_length,
        tampered.as_ptr(),
        tampered.len(),
    );
    assert_eq!(0, result.error_code);
    assert!(!result.is_valid);
}

#[test]
fn ml_dsa_sign_invalid_key_test() {
    let bad_key = vec![0u8; 5];
    let message = b"message".to_vec();
    let signature = ml_dsa_sign_message(bad_key.as_ptr(), bad_key.len(), message.as_ptr(), message.len());
    assert_ne!(0, signature.error_code);
    assert!(signature.signature_ptr.is_null());
}
