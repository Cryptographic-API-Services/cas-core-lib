use std::ffi::c_uchar;

/// AES key derived by `argon2_derive_aes_128_key` / `argon2_derive_aes_256_key`.
///
/// The caller owns `key` (secret) and frees it once with `free_bytes`. It is
/// null when `error_code` is non-zero.
#[repr(C)]
pub struct Argon2KDFAes128 {
    pub key: *mut c_uchar,
    pub length: usize,
    pub error_code: i32,
}