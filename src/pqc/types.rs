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
    pub error_code: i32,
}

#[repr(C)]
pub struct MlDsaKeyPairResult {
    pub signing_key_ptr: *const u8,
    pub signing_key_length: usize,
    pub verification_key_ptr: *const u8,
    pub verification_key_length: usize,
}

#[repr(C)]
pub struct MlDsaSignature {
    pub signature_ptr: *const u8,
    pub signature_length: usize,
    pub error_code: i32,
}

#[repr(C)]
pub struct MlKemKeyPairResult {
    pub secret_key_ptr: *const u8,
    pub secret_key_length: usize,
    pub public_key_ptr: *const u8,
    pub public_key_length: usize,
}

#[repr(C)]
pub struct MlKemEncapsulateResult {
    pub ciphertext_ptr: *const u8,
    pub ciphertext_length: usize,
    pub shared_secret_ptr: *const u8,
    pub shared_secret_length: usize,
    pub error_code: i32,
}

#[repr(C)]
pub struct MlKemDecapsulateResult {
    pub shared_secret_ptr: *const u8,
    pub shared_secret_length: usize,
    pub error_code: i32,
}
