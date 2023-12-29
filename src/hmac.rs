use std::ffi::{c_char, CStr, CString};

use hmac::{Hmac, Mac};
use libc::c_uchar;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[repr(C)]
pub struct HmacSignByteResult {
    pub result_bytes_ptr: *mut c_uchar,
    pub length: usize,
}

#[no_mangle]
pub extern "C" fn hmac_sign_bytes(
    key: *const c_uchar,
    key_length: usize,
    message: *const c_uchar,
    message_length: usize,
) -> HmacSignByteResult {
    assert!(!key.is_null());
    assert!(!message.is_null());
    let key_slice: &[u8] = unsafe { std::slice::from_raw_parts(key, key_length) };
    let message_slice: &[u8] = unsafe { std::slice::from_raw_parts(message, message_length) };
    let mut mac = HmacSha256::new_from_slice(key_slice).unwrap();
    mac.update(message_slice);
    let result = mac.finalize().into_bytes();
    return unsafe {
        let size_of_result = std::mem::size_of_val(&result);
        let result_raw_ptr = libc::malloc(size_of_result) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(result.as_ptr(), result_raw_ptr, size_of_result);
        let result = HmacSignByteResult {
            result_bytes_ptr: result_raw_ptr,
            length: size_of_result,
        };
        result
    };
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
) -> bool {
    assert!(!key.is_null());
    assert!(!message.is_null());
    assert!(!signature.is_null());
    let key_slice: &[u8] = unsafe { std::slice::from_raw_parts(key, key_length) };
    let message_slice: &[u8] = unsafe { std::slice::from_raw_parts(message, message_length) };
    let signature_slice: &[u8] = unsafe { std::slice::from_raw_parts(signature, signature_length) };
    let mut mac = HmacSha256::new_from_slice(key_slice).unwrap();
    mac.update(message_slice);
    return mac.verify_slice(signature_slice).is_ok();
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
    assert_eq!(true, valid);
}
