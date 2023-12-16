use std::ffi::{c_char, CStr, CString};

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[no_mangle]
pub extern "C" fn hmac_sign(key: *const c_char, message: *const c_char) -> *mut c_char {
    let key_bytes = unsafe {
        assert!(!key.is_null());

        CStr::from_ptr(key)
    }
    .to_bytes();

    let message_bytes = unsafe {
        assert!(!message.is_null());

        CStr::from_ptr(message)
    }
    .to_bytes();

    let mut mac = HmacSha256::new_from_slice(key_bytes).unwrap();
    mac.update(message_bytes);
    let result = mac.finalize().into_bytes();
    return CString::new(base64::encode(result)).unwrap().into_raw();
}

#[test]
fn hmac_sign_test() {
    let data_to_sign = "Bad Hmac Test";
    let data_to_sign_ptr = CString::new(data_to_sign).unwrap().into_raw();
    let hmac_key = "ThisIsAHmacKeyBadNewsBears";
    let hmac_key_ptr = CString::new(hmac_key).unwrap().into_raw();
    let result = hmac_sign(hmac_key_ptr, data_to_sign_ptr);
    let result_string = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
    assert_ne!(result_string, data_to_sign);
}

#[no_mangle]
pub extern "C" fn hmac_verify(
    key: *const c_char,
    message: *const c_char,
    signature: *const c_char,
) -> bool {
    let key_bytes = unsafe {
        assert!(!key.is_null());

        CStr::from_ptr(key)
    }
    .to_bytes();

    let message_bytes = unsafe {
        assert!(!message.is_null());

        CStr::from_ptr(message)
    }
    .to_bytes();

    let signature_bytes = unsafe {
        assert!(!signature.is_null());

        CStr::from_ptr(signature)
    }
    .to_str()
    .unwrap();
    let signature_binding = base64::decode(signature_bytes).unwrap();
    let decoded_signature_slice = signature_binding.as_slice();

    let mut mac = HmacSha256::new_from_slice(key_bytes).unwrap();
    mac.update(message_bytes);
    return mac.verify_slice(decoded_signature_slice).is_ok();
}

#[test]
fn hmac_verify_test() {
    let data_to_sign = "Bad Hmac Verify Test";
    let data_to_sign_ptr = CString::new(data_to_sign).unwrap().into_raw();
    let hmac_key = "BadNewsBearsSomeHmacKey";
    let hmac_key_ptr = CString::new(hmac_key).unwrap().into_raw();
    let result = hmac_sign(hmac_key_ptr, data_to_sign_ptr);
    let verify_result = hmac_verify(hmac_key_ptr, data_to_sign_ptr, result);
    assert_eq!(true, verify_result);
}