use std::ffi::c_uchar;

#[repr(C)]
pub struct HpkeKeyPair {
    pub private_key_ptr: *mut c_uchar,
    pub private_key_ptr_length: usize,
    pub public_key_ptr: *mut c_uchar,
    pub public_key_ptr_length: usize
}