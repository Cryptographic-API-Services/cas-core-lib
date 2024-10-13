use std::ffi::c_uchar;

#[repr(C)]
pub struct HpkeKeyPair {
    pub private_key_ptr: *mut c_uchar,
    pub private_key_ptr_length: usize,
    pub public_key_ptr: *mut c_uchar,
    pub public_key_ptr_length: usize,
    pub info_str_ptr: *mut c_uchar,
    pub info_str_ptr_length: usize
}

#[repr(C)]
pub struct HpkeEncrypt {
    pub encapped_key_ptr: *mut c_uchar,
    pub encapped_key_ptr_length: usize,
    pub ciphertext_ptr: *mut c_uchar,
    pub ciphertext_ptr_length: usize,
    pub tag_ptr: *mut c_uchar,
    pub tag_ptr_length: usize
}

#[repr(C)]
pub struct HpkeDecrypt {
    pub plaintext_ptr: *mut c_uchar,
    pub plaintext_ptr_length: usize
}