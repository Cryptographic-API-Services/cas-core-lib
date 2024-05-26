use std::ffi::{c_char, c_uchar};

#[repr(C)]
pub struct RsaKeyPair {
    pub pub_key: *mut c_char,
    pub priv_key: *mut c_char,
}

#[repr(C)]
pub struct RsaSignBytesResults {
    pub signature_raw_ptr: *mut c_uchar,
    pub length: usize,
}

#[repr(C)]
pub struct RsaEncryptBytesResult {
    pub encrypted_result_ptr: *mut c_uchar,
    pub length: usize,
}

#[repr(C)]
pub struct RsaDecryptBytesResult {
    pub decrypted_result_ptr: *mut c_uchar,
    pub length: usize,
}