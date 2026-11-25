use std::ffi::{c_char, c_uchar};

use crate::helpers::free_cstring_field;

/// PEM-encoded RSA key pair from `get_key_pair`.
///
/// The caller owns both strings and must free them: pass the struct to
/// [`free_rsa_key_pair`], or call `free_cstring` (not `free_bytes`) once on
/// each pointer. Both are null when `error_code` is non-zero. `priv_key` is
/// secret.
#[repr(C)]
pub struct RsaKeyPair {
    pub pub_key: *mut c_char,
    pub priv_key: *mut c_char,
    pub error_code: i32,
}

/// RSA signature from `rsa_sign_with_key_bytes`.
///
/// The caller owns `signature_raw_ptr` and frees it with `free_bytes`. It is
/// null when `error_code` is non-zero.
#[repr(C)]
pub struct RsaSignBytesResults {
    pub signature_raw_ptr: *mut c_uchar,
    pub length: usize,
    pub error_code: i32,
}

/// Frees both strings of an [`RsaKeyPair`] and nulls its fields, so a second
/// call is harmless. A null `result` (or null fields, after an error) is
/// ignored.
#[no_mangle]
pub extern "C" fn free_rsa_key_pair(result: *mut RsaKeyPair) {
    let Some(result) = (unsafe { result.as_mut() }) else { return };
    free_cstring_field(&mut result.pub_key);
    free_cstring_field(&mut result.priv_key);
}

#[test]
fn free_rsa_results_test() {
    use crate::helpers::free_bytes;
    use crate::rsa::{get_key_pair, rsa_sign_with_key_bytes};

    let data = b"free every RSA result".to_vec();
    let mut key_pair = get_key_pair(2048);
    assert_eq!(0, key_pair.error_code);
    let signature = rsa_sign_with_key_bytes(key_pair.priv_key, data.as_ptr(), data.len());
    assert_eq!(0, signature.error_code);
    free_bytes(signature.signature_raw_ptr);

    free_rsa_key_pair(&mut key_pair);
    assert!(key_pair.pub_key.is_null() && key_pair.priv_key.is_null());
    free_rsa_key_pair(&mut key_pair);
    free_rsa_key_pair(std::ptr::null_mut());
}
