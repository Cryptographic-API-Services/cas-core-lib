use std::ffi::c_uchar;

#[repr(C)]
pub struct SHAHashByteResult {
    pub result_bytes_ptr: *mut c_uchar,
    pub length: usize,
}