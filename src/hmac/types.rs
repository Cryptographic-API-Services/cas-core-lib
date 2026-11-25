use std::ffi::c_uchar;

/// HMAC tag from `hmac_sign_bytes`.
///
/// The caller owns `result_bytes_ptr` and frees it once with `free_bytes`. It is
/// null when `error_code` is non-zero.
#[repr(C)]
pub struct HmacSignByteResult {
    pub result_bytes_ptr: *mut c_uchar,
    pub length: usize,
    pub error_code: i32,
}