use cas_lib::pqc::slh_dsa::{generate_signing_and_verification_key, sign_message, verify_signature};
use crate::pqc::types::{SlhDsaKeyPairResult, SlhDsaSignature};
use crate::helpers::{cas_error_code, CasVerifyResult};

#[no_mangle]
pub extern "C" fn slh_dsa_generate_signing_and_verification_key() -> SlhDsaKeyPairResult {
    let key_pair: cas_lib::pqc::cas_pqc::SlhDsaKeyPair = generate_signing_and_verification_key();
    let result = SlhDsaKeyPairResult {
        signing_key_ptr: key_pair.signing_key.as_ptr(),
        signing_key_length: key_pair.signing_key.len(),
        verification_key_ptr: key_pair.verification_key.as_ptr(),
        verification_key_length: key_pair.verification_key.len(),
    };
    std::mem::forget(key_pair.signing_key);
    std::mem::forget(key_pair.verification_key);
    result
}

#[no_mangle]
pub extern "C" fn slh_dsa_sign_message(
    signing_key: *const u8,
    signing_key_length: usize,
    message: *const u8,
    message_length: usize,
) -> SlhDsaSignature {
    let signing_key_slice = unsafe {
        assert!(!signing_key.is_null());
        std::slice::from_raw_parts(signing_key, signing_key_length)
    }
    .to_vec();
    let message_slice = unsafe {
        assert!(!message.is_null());
        std::slice::from_raw_parts(message, message_length)
    }
    .to_vec();
    match sign_message(message_slice, signing_key_slice) {
        Ok(signature) => {
            let result = SlhDsaSignature {
                signature_ptr: signature.as_ptr(),
                signature_length: signature.len(),
                error_code: 0,
            };
            std::mem::forget(signature);
            result
        }
        Err(e) => SlhDsaSignature {
            signature_ptr: std::ptr::null(),
            signature_length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

#[no_mangle]
pub extern "C" fn slh_dsa_verify_signature(
    verification_key: *const u8,
    verification_key_length: usize,
    signature: *const u8,
    signature_length: usize,
    message: *const u8,
    message_length: usize,
) -> CasVerifyResult {
    let verification_key_slice = unsafe {
        assert!(!verification_key.is_null());
        std::slice::from_raw_parts(verification_key, verification_key_length)
    }
    .to_vec();
    let signature_slice = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }
    .to_vec();
    let message_slice = unsafe {
        assert!(!message.is_null());
        std::slice::from_raw_parts(message, message_length)
    }
    .to_vec();
    match verify_signature(message_slice, signature_slice, verification_key_slice) {
        Ok(is_valid) => CasVerifyResult { is_valid, error_code: 0 },
        Err(e) => CasVerifyResult { is_valid: false, error_code: cas_error_code(&e) },
    }
}