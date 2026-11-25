use cas_lib::signatures::ed25519::{ed25519_sign_with_key_pair,  ed25519_verify_with_key_pair,  ed25519_verify_with_public_key,  get_ed25519_key_pair};
use libc::c_uchar;

use crate::helpers::{cas_error_code, export_bytes, free_bytes_field, CasVerifyResult};

/// Ed25519 key pair from `get_ed25519_key_pair_bytes`.
///
/// The caller owns both buffers and must free them: pass the struct to
/// [`free_ed25519_key_pair_bytes_result`], or call `free_bytes` once on each
/// pointer. `signing_key` (the full key pair) is secret.
#[repr(C)]
pub struct Ed25519KeyPairBytesResult {
    signing_key: *mut c_uchar,
    signing_key_length: usize,
    verifying_key: *mut c_uchar,
    verifying_key_length: usize,
}

/// Ed25519 signature and public key from `sign_with_key_pair_bytes`.
///
/// The caller owns both buffers and must free them: pass the struct to
/// [`free_ed25519_byte_signature_result`], or call `free_bytes` once on each
/// pointer. Both are null when `error_code` is non-zero.
#[repr(C)]
pub struct Ed25519ByteSignatureResult {
    pub signature_byte_ptr: *mut c_uchar,
    pub signature_length: usize,
    pub public_key: *mut c_uchar,
    pub public_key_length: usize,
    pub error_code: i32,
}

#[no_mangle]
pub extern "C" fn get_ed25519_key_pair_bytes() -> Ed25519KeyPairBytesResult {
    let keypair = get_ed25519_key_pair();
    let result = Ed25519KeyPairBytesResult {
        signing_key_length: keypair.key_pair.len(),
        signing_key: export_bytes(&keypair.key_pair),
        verifying_key_length: keypair.public_key.len(),
        verifying_key: export_bytes(&keypair.public_key),
    };
    result
}


#[test]
fn get_ed25519_key_pair_bytes_test() {
    let key_pair_result = get_ed25519_key_pair_bytes();
    assert_eq!(false, key_pair_result.signing_key.is_null());
    assert_eq!(true, key_pair_result.signing_key_length > 0);
    assert_eq!(false, key_pair_result.verifying_key.is_null());
    assert_eq!(true, key_pair_result.verifying_key_length > 0);
}

#[no_mangle]
pub extern "C" fn sign_with_key_pair_bytes(
    key_pair: *const c_uchar,
    key_pair_length: usize,
    message_to_sign: *const c_uchar,
    message_to_sign_length: usize,
) -> Ed25519ByteSignatureResult {
    let key_pair_slice = unsafe {
        assert!(!key_pair.is_null());
        std::slice::from_raw_parts(key_pair, key_pair_length)
    }
    .to_vec();
    let message_to_sign_slice = unsafe {
        assert!(!message_to_sign.is_null());
        std::slice::from_raw_parts(message_to_sign, message_to_sign_length)
    }
    .to_vec();
    match ed25519_sign_with_key_pair(key_pair_slice, message_to_sign_slice) {
        Ok(result) => {
            let public_key = result.public_key;
            let signature = result.signature;
            let result = Ed25519ByteSignatureResult {
                signature_byte_ptr: export_bytes(&signature),
                signature_length: signature.len(),
                public_key: export_bytes(&public_key),
                public_key_length: public_key.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => Ed25519ByteSignatureResult {
            signature_byte_ptr: std::ptr::null_mut(),
            signature_length: 0,
            public_key: std::ptr::null_mut(),
            public_key_length: 0,
            error_code: cas_error_code(&e),
        },
    }
}


#[test]
fn sign_with_key_pair_bytes_test() {
    let key_pair_result: Ed25519KeyPairBytesResult = get_ed25519_key_pair_bytes();
    let message: &str = "ThisIsAMessageToSignWithED25519Dalek";
    let message_byte: &[u8] = message.as_bytes();
    let signature_result: Ed25519ByteSignatureResult = sign_with_key_pair_bytes(
        key_pair_result.signing_key,
        key_pair_result.signing_key_length,
        message_byte.as_ptr(),
        message_byte.len(),
    );
    assert_eq!(false, signature_result.public_key.is_null());
    assert_eq!(true, signature_result.public_key_length > 0);
    assert_eq!(false, signature_result.signature_byte_ptr.is_null());
    assert_eq!(true, signature_result.signature_length > 0);
}

#[no_mangle]
pub extern "C" fn verify_with_key_pair_bytes(
    key_pair: *const c_uchar,
    key_pair_length: usize,
    signature: *const c_uchar,
    signature_length: usize,
    message: *const c_uchar,
    message_length: usize,
) -> CasVerifyResult {
    let key_pair_slice = unsafe {
        assert!(!key_pair.is_null());
        std::slice::from_raw_parts(key_pair, key_pair_length)
    }.to_vec();
    let signature_slice = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }.to_vec();
    let message_slice = unsafe {
        assert!(!message.is_null());
        std::slice::from_raw_parts(message, message_length)
    }.to_vec();
    match ed25519_verify_with_key_pair(key_pair_slice, signature_slice, message_slice) {
        Ok(is_valid) => CasVerifyResult { is_valid, error_code: 0 },
        Err(e) => CasVerifyResult { is_valid: false, error_code: cas_error_code(&e) },
    }
}


#[test]
fn verify_with_key_pair_bytes_test() {
    let key_pair = get_ed25519_key_pair_bytes();
    let message = "SignThisMessageWithED25519Dalek".as_bytes();
    let sign_result: Ed25519ByteSignatureResult = sign_with_key_pair_bytes(
        key_pair.signing_key,
        key_pair.signing_key_length,
        message.as_ptr(),
        message.len(),
    );
    let is_valid = verify_with_key_pair_bytes(
        key_pair.signing_key,
        key_pair.signing_key_length,
        sign_result.signature_byte_ptr,
        sign_result.signature_length,
        message.as_ptr(),
        message.len(),
    );
    assert_eq!(true, is_valid.is_valid);
}

#[no_mangle]
pub extern "C" fn verify_with_public_key_bytes(
    public_key: *const c_uchar,
    public_key_length: usize,
    signature: *const c_uchar,
    signature_length: usize,
    message: *const c_uchar,
    message_length: usize,
) -> CasVerifyResult {
    let public_key_slice = unsafe {
        assert!(!public_key.is_null());
        std::slice::from_raw_parts(public_key, public_key_length)
    }.to_vec();
    let signature_slice = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }.to_vec();
    let message_slice = unsafe {
        assert!(!message.is_null());
        std::slice::from_raw_parts(message, message_length)
    }.to_vec();
    match ed25519_verify_with_public_key(public_key_slice, signature_slice, message_slice) {
        Ok(is_valid) => CasVerifyResult { is_valid, error_code: 0 },
        Err(e) => CasVerifyResult { is_valid: false, error_code: cas_error_code(&e) },
    }
}

#[test]
fn verify_with_public_key_bytes_test() {
    let key_pair = get_ed25519_key_pair_bytes();
    let message = "SignThisMessageWithED25519Dalek".as_bytes();
    let signature_result: Ed25519ByteSignatureResult = sign_with_key_pair_bytes(
        key_pair.signing_key,
        key_pair.signing_key_length,
        message.as_ptr(),
        message.len(),
    );
    let is_valid = verify_with_public_key_bytes(
        signature_result.public_key,
        signature_result.public_key_length,
        signature_result.signature_byte_ptr,
        signature_result.signature_length,
        message.as_ptr(),
        message.len(),
    );
    assert_eq!(true, is_valid.is_valid);
}

/// Frees both buffers of an [`Ed25519KeyPairBytesResult`] and nulls its
/// fields, so a second call is harmless. A null `result` is ignored.
#[no_mangle]
pub extern "C" fn free_ed25519_key_pair_bytes_result(result: *mut Ed25519KeyPairBytesResult) {
    let Some(result) = (unsafe { result.as_mut() }) else { return };
    free_bytes_field(&mut result.signing_key, &mut result.signing_key_length);
    free_bytes_field(&mut result.verifying_key, &mut result.verifying_key_length);
}

/// Frees both buffers of an [`Ed25519ByteSignatureResult`] and nulls its
/// fields, so a second call is harmless. A null `result` (or null fields, after
/// an error) is ignored.
#[no_mangle]
pub extern "C" fn free_ed25519_byte_signature_result(result: *mut Ed25519ByteSignatureResult) {
    let Some(result) = (unsafe { result.as_mut() }) else { return };
    free_bytes_field(&mut result.signature_byte_ptr, &mut result.signature_length);
    free_bytes_field(&mut result.public_key, &mut result.public_key_length);
}

#[test]
fn free_ed25519_results_test() {
    let mut key_pair = get_ed25519_key_pair_bytes();
    let message = "FreeEveryEd25519Result".as_bytes();
    let mut signature = sign_with_key_pair_bytes(
        key_pair.signing_key,
        key_pair.signing_key_length,
        message.as_ptr(),
        message.len(),
    );
    assert_eq!(0, signature.error_code);

    free_ed25519_byte_signature_result(&mut signature);
    assert!(signature.signature_byte_ptr.is_null() && signature.public_key.is_null());
    assert_eq!(0, signature.signature_length + signature.public_key_length);
    free_ed25519_byte_signature_result(&mut signature);

    free_ed25519_key_pair_bytes_result(&mut key_pair);
    assert!(key_pair.signing_key.is_null() && key_pair.verifying_key.is_null());
    free_ed25519_key_pair_bytes_result(&mut key_pair);

    free_ed25519_byte_signature_result(std::ptr::null_mut());
    free_ed25519_key_pair_bytes_result(std::ptr::null_mut());
}
