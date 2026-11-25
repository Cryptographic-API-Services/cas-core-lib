use std::ffi::c_uchar;

/// SHA-2 / SHA-3 digest from the `sha*_bytes` functions.
///
/// The caller owns `result_bytes_ptr` and frees it once with `free_bytes`.
#[repr(C)]
pub struct SHAHashByteResult {
    pub result_bytes_ptr: *mut c_uchar,
    pub length: usize,
}