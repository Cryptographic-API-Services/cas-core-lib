use std::ffi::c_uchar;

use crate::helpers::free_bytes_field;

/// HPKE key pair from `hpke_generate_keypair`.
///
/// The caller owns all three buffers and must free them: pass the struct to
/// [`free_hpke_key_pair`], or call `free_bytes` once on each pointer.
/// `private_key_ptr` is secret.
#[repr(C)]
pub struct HpkeKeyPair {
    pub private_key_ptr: *mut c_uchar,
    pub private_key_ptr_length: usize,
    pub public_key_ptr: *mut c_uchar,
    pub public_key_ptr_length: usize,
    pub info_str_ptr: *mut c_uchar,
    pub info_str_ptr_length: usize
}

/// HPKE ciphertext from `hpke_encrypt`.
///
/// The caller owns all three buffers and must free them: pass the struct to
/// [`free_hpke_encrypt`], or call `free_bytes` once on each pointer. All three
/// are null when `error_code` is non-zero.
#[repr(C)]
pub struct HpkeEncrypt {
    pub encapped_key_ptr: *mut c_uchar,
    pub encapped_key_ptr_length: usize,
    pub ciphertext_ptr: *mut c_uchar,
    pub ciphertext_ptr_length: usize,
    pub tag_ptr: *mut c_uchar,
    pub tag_ptr_length: usize,
    pub error_code: i32,
}

/// HPKE plaintext from `hpke_decrypt`.
///
/// The caller owns `plaintext_ptr` and frees it with `free_bytes`. It is null
/// when `error_code` is non-zero.
#[repr(C)]
pub struct HpkeDecrypt {
    pub plaintext_ptr: *mut c_uchar,
    pub plaintext_ptr_length: usize,
    pub error_code: i32,
}

/// Frees the three buffers of an [`HpkeKeyPair`] and nulls its fields, so a
/// second call is harmless. A null `result` is ignored.
#[no_mangle]
pub extern "C" fn free_hpke_key_pair(result: *mut HpkeKeyPair) {
    let Some(result) = (unsafe { result.as_mut() }) else { return };
    free_bytes_field(&mut result.private_key_ptr, &mut result.private_key_ptr_length);
    free_bytes_field(&mut result.public_key_ptr, &mut result.public_key_ptr_length);
    free_bytes_field(&mut result.info_str_ptr, &mut result.info_str_ptr_length);
}

/// Frees the three buffers of an [`HpkeEncrypt`] and nulls its fields, so a
/// second call is harmless. A null `result` (or null fields, after an error)
/// is ignored.
#[no_mangle]
pub extern "C" fn free_hpke_encrypt(result: *mut HpkeEncrypt) {
    let Some(result) = (unsafe { result.as_mut() }) else { return };
    free_bytes_field(&mut result.encapped_key_ptr, &mut result.encapped_key_ptr_length);
    free_bytes_field(&mut result.ciphertext_ptr, &mut result.ciphertext_ptr_length);
    free_bytes_field(&mut result.tag_ptr, &mut result.tag_ptr_length);
}

#[test]
fn free_hpke_results_test() {
    use crate::helpers::free_bytes;
    use crate::hpke::{hpke_decrypt, hpke_encrypt, hpke_generate_keypair};

    let plaintext = b"free every HPKE result".to_vec();
    let mut key_pair = hpke_generate_keypair();
    let mut encrypted = hpke_encrypt(
        plaintext.as_ptr(),
        plaintext.len(),
        key_pair.public_key_ptr,
        key_pair.public_key_ptr_length,
        key_pair.info_str_ptr,
        key_pair.info_str_ptr_length,
    );
    assert_eq!(0, encrypted.error_code);
    let decrypted = hpke_decrypt(
        encrypted.ciphertext_ptr,
        encrypted.ciphertext_ptr_length,
        key_pair.private_key_ptr,
        key_pair.private_key_ptr_length,
        encrypted.encapped_key_ptr,
        encrypted.encapped_key_ptr_length,
        encrypted.tag_ptr,
        encrypted.tag_ptr_length,
        key_pair.info_str_ptr,
        key_pair.info_str_ptr_length,
    );
    assert_eq!(0, decrypted.error_code);
    free_bytes(decrypted.plaintext_ptr);

    free_hpke_encrypt(&mut encrypted);
    assert!(encrypted.encapped_key_ptr.is_null() && encrypted.ciphertext_ptr.is_null() && encrypted.tag_ptr.is_null());
    assert_eq!(0, encrypted.encapped_key_ptr_length + encrypted.ciphertext_ptr_length + encrypted.tag_ptr_length);
    free_hpke_encrypt(&mut encrypted);

    free_hpke_key_pair(&mut key_pair);
    assert!(key_pair.private_key_ptr.is_null() && key_pair.public_key_ptr.is_null() && key_pair.info_str_ptr.is_null());
    free_hpke_key_pair(&mut key_pair);

    free_hpke_key_pair(std::ptr::null_mut());
    free_hpke_encrypt(std::ptr::null_mut());
}
