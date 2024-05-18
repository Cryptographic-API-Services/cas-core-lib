use std::ffi::c_uchar;

#[repr(C)]
pub struct HmacSignByteResult {
    pub result_bytes_ptr: *mut c_uchar,
    pub length: usize,
}