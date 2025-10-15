use cas_lib::pqc::slh_dsa::{generate_signing_and_verification_key, sign_message, verify_signature};
use crate::pqc::types::{SlhDsaKeyPairResult, SlhDsaSignature};

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
    key_pair: *const u8,
    key_pair_length: usize,
    message: *const u8,
    message_length: usize,
) -> SlhDsaSignature {
    let key_pair_slice = unsafe {
        assert!(!key_pair.is_null());
        std::slice::from_raw_parts(key_pair, key_pair_length)
    }
    .to_vec();
    let message_slice = unsafe {
        assert!(!message.is_null());
        std::slice::from_raw_parts(message, message_length)
    }
    .to_vec();
    let signature: Vec<u8> = sign_message(key_pair_slice, message_slice);
    let result = SlhDsaSignature {
        signature_ptr: signature.as_ptr(),
        signature_length: signature.len(),
    };
    std::mem::forget(signature);
    result
}

#[no_mangle]
pub extern "C" fn slh_dsa_verify_signature(
    public_key: *const u8,
    public_key_length: usize,
    signature: *const u8,
    signature_length: usize,
    message: *const u8,
    message_length: usize,
) -> bool {
    let public_key_slice = unsafe {
        assert!(!public_key.is_null());
        std::slice::from_raw_parts(public_key, public_key_length)
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
    verify_signature(public_key_slice, signature_slice, message_slice)
}