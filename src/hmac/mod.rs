use cas_lib::message::{cas_hmac::CASHMAC, hmac::HMAC};
use libc::c_uchar;

use self::types::HmacSignByteResult;
use crate::helpers::{cas_error_code, CasVerifyResult};

mod types;

#[no_mangle]
pub extern "C" fn hmac_sign_bytes(
    key: *const c_uchar,
    key_length: usize,
    message: *const c_uchar,
    message_length: usize,
) -> HmacSignByteResult {
    assert!(!key.is_null());
    assert!(!message.is_null());
    let key_slice: Vec<u8> = unsafe { std::slice::from_raw_parts(key, key_length) }.to_vec();
    let message_slice: Vec<u8> =
        unsafe { std::slice::from_raw_parts(message, message_length) }.to_vec();
    match <HMAC as CASHMAC>::sign(key_slice, message_slice) {
        Ok(mut result) => {
            let capacity = result.capacity();
            result.reserve_exact(capacity);
            let return_result = HmacSignByteResult {
                result_bytes_ptr: result.as_mut_ptr(),
                length: result.len(),
                error_code: 0,
            };
            std::mem::forget(result);
            return_result
        }
        Err(e) => HmacSignByteResult {
            result_bytes_ptr: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

#[test]
fn hmac_sign_bytes_test() {
    let data_to_sign = "Bad Hmac Test";
    let data_to_sign_bytes: &[u8] = data_to_sign.as_bytes();
    let data_to_sign_length: usize = data_to_sign_bytes.len();
    let hmac_key = "ThisIsAHmacKeyBadNewsBears";
    let hmac_key_bytes = hmac_key.as_bytes();
    let hmac_key_bytes_length = hmac_key_bytes.len();
    let result: HmacSignByteResult = hmac_sign_bytes(
        hmac_key_bytes.as_ptr(),
        hmac_key_bytes_length,
        data_to_sign_bytes.as_ptr(),
        data_to_sign_length,
    );
    assert_ne!(data_to_sign_bytes.as_ptr(), result.result_bytes_ptr);
}

#[no_mangle]
pub extern "C" fn hmac_verify_bytes(
    key: *const c_uchar,
    key_length: usize,
    message: *const c_uchar,
    message_length: usize,
    signature: *const c_uchar,
    signature_length: usize,
) -> CasVerifyResult {
    assert!(!key.is_null());
    assert!(!message.is_null());
    assert!(!signature.is_null());
    let key_slice: Vec<u8> = unsafe { std::slice::from_raw_parts(key, key_length) }.to_vec();
    let message_slice: Vec<u8> = unsafe { std::slice::from_raw_parts(message, message_length) }.to_vec();
    let signature_slice: Vec<u8> = unsafe { std::slice::from_raw_parts(signature, signature_length) }.to_vec();
    match <HMAC as CASHMAC>::verify(key_slice, message_slice, signature_slice) {
        Ok(is_valid) => CasVerifyResult { is_valid, error_code: 0 },
        Err(e) => CasVerifyResult { is_valid: false, error_code: cas_error_code(&e) },
    }
}

#[test]
fn hmac_verify_bytes_test() {
    let data_to_sign = "Bad Hmac Test 1234567890";
    let data_to_sign_bytes: &[u8] = data_to_sign.as_bytes();
    let data_to_sign_length: usize = data_to_sign_bytes.len();
    let hmac_key = "ThisIsAHmacKeyBadNewsBears";
    let hmac_key_bytes = hmac_key.as_bytes();
    let hmac_key_bytes_length = hmac_key_bytes.len();
    let result: HmacSignByteResult = hmac_sign_bytes(
        hmac_key_bytes.as_ptr(),
        hmac_key_bytes_length,
        data_to_sign_bytes.as_ptr(),
        data_to_sign_length,
    );
    let valid = hmac_verify_bytes(
        hmac_key_bytes.as_ptr(),
        hmac_key_bytes_length,
        data_to_sign_bytes.as_ptr(),
        data_to_sign_length,
        result.result_bytes_ptr,
        result.length,
    );
    assert_eq!(true, valid.is_valid);
}
