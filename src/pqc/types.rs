#[repr(C)]
pub struct SlhDsaKeyPairResult {
    pub signing_key_ptr: *const u8,
    pub signing_key_length: usize,
    pub verification_key_ptr: *const u8,
    pub verification_key_length: usize,
}

#[repr(C)]
pub struct SlhDsaSignature {
    pub signature_ptr: *const u8,
    pub signature_length: usize,
}