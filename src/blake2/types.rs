use std::ffi::c_uchar;

/// BLAKE2 digest from `blake2_256_bytes` / `blake2_512_bytes`.
///
/// The caller owns `result_bytes_ptr` and frees it once with `free_bytes`.
#[repr(C)]
pub struct Blake2HashByteResult {
    pub result_bytes_ptr: *mut c_uchar,
    pub length: usize,
    /// `0` on success. `InvalidInput` (4) for a null pointer with a non-zero length
    /// or a length above `isize::MAX`.
    pub error_code: i32,
}