use std::ffi::c_uchar;

#[repr(C)]
pub struct Blake2HashByteResult {
    pub result_bytes_ptr: *mut c_uchar,
    pub length: usize,
}