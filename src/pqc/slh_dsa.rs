use cas_lib::pqc::slh_dsa::{generate_signing_and_verification_key, sign_message, verify_signature};
use crate::pqc::types::{SlhDsaKeyPairResult, SlhDsaSignature};
use crate::helpers::{bytes_from_ffi, cas_error_code, export_bytes, CasVerifyResult};

#[no_mangle]
pub extern "C" fn slh_dsa_generate_signing_and_verification_key() -> SlhDsaKeyPairResult {
    let key_pair: cas_lib::pqc::cas_pqc::SlhDsaKeyPair = generate_signing_and_verification_key();
    let result = SlhDsaKeyPairResult {
        signing_key_ptr: export_bytes(&key_pair.signing_key),
        signing_key_length: key_pair.signing_key.len(),
        verification_key_ptr: export_bytes(&key_pair.verification_key),
        verification_key_length: key_pair.verification_key.len(),
        error_code: 0,
    };
    result
}

#[no_mangle]
pub extern "C" fn slh_dsa_sign_message(
    signing_key: *const u8,
    signing_key_length: usize,
    message: *const u8,
    message_length: usize,
) -> SlhDsaSignature {
    match (|| {
        let signing_key_slice = bytes_from_ffi(signing_key, signing_key_length)?;
        let message_slice = bytes_from_ffi(message, message_length)?;
        sign_message(message_slice, signing_key_slice)
    })() {
        Ok(signature) => {
            let result = SlhDsaSignature {
                signature_ptr: export_bytes(&signature),
                signature_length: signature.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => SlhDsaSignature {
            signature_ptr: std::ptr::null_mut(),
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