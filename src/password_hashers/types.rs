use std::ffi::c_uchar;

#[repr(C)]
pub struct Argon2KDFAes128 {
    pub key: *mut c_uchar,
    pub length: usize,
}