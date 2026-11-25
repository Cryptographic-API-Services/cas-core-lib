use std::ffi::c_uchar;

/// AES key derived by the deprecated `argon2_derive_aes_128_key` /
/// `argon2_derive_aes_256_key` (despite the name, the 256-bit function returns
/// it too).
///
/// The caller owns `key` (secret) and frees it once with `free_bytes`. It is
/// null when `error_code` is non-zero.
#[repr(C)]
pub struct Argon2KDFAes128 {
    pub key: *mut c_uchar,
    pub length: usize,
    pub error_code: i32,
}

/// A salt from `argon2_generate_salt`. Free `salt` with `free_bytes`.
#[repr(C)]
pub struct Argon2Salt {
    pub salt: *mut c_uchar,
    pub length: usize,
    /// `0` on success. Generation takes no caller input.
    pub error_code: i32,
}

/// A key from `argon2_derive_aes_128_key_with_salt` / `argon2_derive_aes_256_key_with_salt`.
/// `key` is null when `error_code` is non-zero; otherwise free it with `free_bytes`.
#[repr(C)]
pub struct Argon2DerivedKey {
    pub key: *mut c_uchar,
    pub length: usize,
    pub error_code: i32,
}
