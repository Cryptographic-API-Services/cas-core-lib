use cas_lib::pqc::cas_pqc::{SlhDsaKeyPair};
use cas_lib::pqc::slh_dsa::{generate_signing_and_verification_key, sign_message, verify_signature};

#[no_mangle]
pub extern "C" fn slh_dsa_generate_signing_and_verification_key() -> SlhDsaKeyPair {
    generate_signing_and_verification_key()
}

#[no_mangle]
pub extern "C" fn slh_dsa_sign_message(
    key_pair: *const u8,
    key_pair_length: usize,
    message: *const u8,
    message_length: usize,
) -> Vec<u8> {
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
    sign_message(key_pair_slice, message_slice)
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