use crate::helpers::free_bytes_field;

/// SLH-DSA key pair from `slh_dsa_generate_signing_and_verification_key`.
///
/// The caller owns both buffers and must free them: pass the struct to
/// [`free_slh_dsa_key_pair_result`], or call `free_bytes` once on each pointer.
/// `signing_key_ptr` is secret.
#[repr(C)]
pub struct SlhDsaKeyPairResult {
    pub signing_key_ptr: *mut u8,
    pub signing_key_length: usize,
    pub verification_key_ptr: *mut u8,
    pub verification_key_length: usize,
    /// `0` on success. Generation takes no caller input.
    pub error_code: i32,
}

/// SLH-DSA signature from `slh_dsa_sign_message`.
///
/// The caller owns `signature_ptr` and frees it with `free_bytes`. It is null
/// when `error_code` is non-zero.
#[repr(C)]
pub struct SlhDsaSignature {
    pub signature_ptr: *mut u8,
    pub signature_length: usize,
    pub error_code: i32,
}

/// ML-DSA key pair from `ml_dsa_generate_signing_and_verification_key`.
///
/// The caller owns both buffers and must free them: pass the struct to
/// [`free_ml_dsa_key_pair_result`], or call `free_bytes` once on each pointer.
/// `signing_key_ptr` is secret.
#[repr(C)]
pub struct MlDsaKeyPairResult {
    pub signing_key_ptr: *mut u8,
    pub signing_key_length: usize,
    pub verification_key_ptr: *mut u8,
    pub verification_key_length: usize,
    /// `0` on success. Generation takes no caller input.
    pub error_code: i32,
}

/// ML-DSA signature from `ml_dsa_sign_message`.
///
/// The caller owns `signature_ptr` and frees it with `free_bytes`. It is null
/// when `error_code` is non-zero.
#[repr(C)]
pub struct MlDsaSignature {
    pub signature_ptr: *mut u8,
    pub signature_length: usize,
    pub error_code: i32,
}

/// ML-KEM-1024 key pair from `ml_kem_1024_generate_key_pair`.
///
/// The caller owns both buffers and must free them: pass the struct to
/// [`free_ml_kem_key_pair_result`], or call `free_bytes` once on each pointer.
/// `secret_key_ptr` is secret.
#[repr(C)]
pub struct MlKemKeyPairResult {
    pub secret_key_ptr: *mut u8,
    pub secret_key_length: usize,
    pub public_key_ptr: *mut u8,
    pub public_key_length: usize,
    /// `0` on success. Generation takes no caller input.
    pub error_code: i32,
}

/// ML-KEM-1024 encapsulation from `ml_kem_1024_encapsulate_shared_secret`.
///
/// The caller owns both buffers and must free them: pass the struct to
/// [`free_ml_kem_encapsulate_result`], or call `free_bytes` once on each
/// pointer. Both are null when `error_code` is non-zero. `shared_secret_ptr` is
/// secret.
#[repr(C)]
pub struct MlKemEncapsulateResult {
    pub ciphertext_ptr: *mut u8,
    pub ciphertext_length: usize,
    pub shared_secret_ptr: *mut u8,
    pub shared_secret_length: usize,
    pub error_code: i32,
}

/// ML-KEM-1024 decapsulation from `ml_kem_1024_decapsulate_shared_secret`.
///
/// The caller owns `shared_secret_ptr` (secret) and frees it with
/// `free_bytes`. It is null when `error_code` is non-zero.
#[repr(C)]
pub struct MlKemDecapsulateResult {
    pub shared_secret_ptr: *mut u8,
    pub shared_secret_length: usize,
    pub error_code: i32,
}

/// Frees both buffers of an [`SlhDsaKeyPairResult`] and nulls its fields, so a
/// second call is harmless. A null `result` is ignored.
#[no_mangle]
pub extern "C" fn free_slh_dsa_key_pair_result(result: *mut SlhDsaKeyPairResult) {
    let Some(result) = (unsafe { result.as_mut() }) else { return };
    free_bytes_field(&mut result.signing_key_ptr, &mut result.signing_key_length);
    free_bytes_field(&mut result.verification_key_ptr, &mut result.verification_key_length);
}

/// Frees both buffers of an [`MlDsaKeyPairResult`] and nulls its fields, so a
/// second call is harmless. A null `result` is ignored.
#[no_mangle]
pub extern "C" fn free_ml_dsa_key_pair_result(result: *mut MlDsaKeyPairResult) {
    let Some(result) = (unsafe { result.as_mut() }) else { return };
    free_bytes_field(&mut result.signing_key_ptr, &mut result.signing_key_length);
    free_bytes_field(&mut result.verification_key_ptr, &mut result.verification_key_length);
}

/// Frees both buffers of an [`MlKemKeyPairResult`] and nulls its fields, so a
/// second call is harmless. A null `result` is ignored.
#[no_mangle]
pub extern "C" fn free_ml_kem_key_pair_result(result: *mut MlKemKeyPairResult) {
    let Some(result) = (unsafe { result.as_mut() }) else { return };
    free_bytes_field(&mut result.secret_key_ptr, &mut result.secret_key_length);
    free_bytes_field(&mut result.public_key_ptr, &mut result.public_key_length);
}

/// Frees both buffers of an [`MlKemEncapsulateResult`] and nulls its fields,
/// so a second call is harmless. A null `result` (or null fields, after an
/// error) is ignored.
#[no_mangle]
pub extern "C" fn free_ml_kem_encapsulate_result(result: *mut MlKemEncapsulateResult) {
    let Some(result) = (unsafe { result.as_mut() }) else { return };
    free_bytes_field(&mut result.ciphertext_ptr, &mut result.ciphertext_length);
    free_bytes_field(&mut result.shared_secret_ptr, &mut result.shared_secret_length);
}

#[test]
fn free_pqc_results_test() {
    use crate::helpers::free_bytes;
    use crate::pqc::{ml_dsa, ml_kem, slh_dsa};

    let message = b"free every PQC result".to_vec();

    let mut slh_keys = slh_dsa::slh_dsa_generate_signing_and_verification_key();
    let slh_signature = slh_dsa::slh_dsa_sign_message(
        slh_keys.signing_key_ptr,
        slh_keys.signing_key_length,
        message.as_ptr(),
        message.len(),
    );
    assert_eq!(0, slh_signature.error_code);
    free_bytes(slh_signature.signature_ptr);
    free_slh_dsa_key_pair_result(&mut slh_keys);
    assert!(slh_keys.signing_key_ptr.is_null() && slh_keys.verification_key_ptr.is_null());
    assert_eq!(0, slh_keys.signing_key_length + slh_keys.verification_key_length);
    free_slh_dsa_key_pair_result(&mut slh_keys);

    let mut ml_dsa_keys = ml_dsa::ml_dsa_generate_signing_and_verification_key();
    let ml_dsa_signature = ml_dsa::ml_dsa_sign_message(
        ml_dsa_keys.signing_key_ptr,
        ml_dsa_keys.signing_key_length,
        message.as_ptr(),
        message.len(),
    );
    assert_eq!(0, ml_dsa_signature.error_code);
    free_bytes(ml_dsa_signature.signature_ptr);
    free_ml_dsa_key_pair_result(&mut ml_dsa_keys);
    assert!(ml_dsa_keys.signing_key_ptr.is_null() && ml_dsa_keys.verification_key_ptr.is_null());
    free_ml_dsa_key_pair_result(&mut ml_dsa_keys);

    let mut ml_kem_keys = ml_kem::ml_kem_1024_generate_key_pair();
    let mut encap = ml_kem::ml_kem_1024_encapsulate_shared_secret(
        ml_kem_keys.public_key_ptr,
        ml_kem_keys.public_key_length,
    );
    assert_eq!(0, encap.error_code);
    let decap = ml_kem::ml_kem_1024_decapsulate_shared_secret(
        ml_kem_keys.secret_key_ptr,
        ml_kem_keys.secret_key_length,
        encap.ciphertext_ptr,
        encap.ciphertext_length,
    );
    assert_eq!(0, decap.error_code);
    free_bytes(decap.shared_secret_ptr);
    free_ml_kem_encapsulate_result(&mut encap);
    assert!(encap.ciphertext_ptr.is_null() && encap.shared_secret_ptr.is_null());
    free_ml_kem_encapsulate_result(&mut encap);
    free_ml_kem_key_pair_result(&mut ml_kem_keys);
    assert!(ml_kem_keys.secret_key_ptr.is_null() && ml_kem_keys.public_key_ptr.is_null());
    free_ml_kem_key_pair_result(&mut ml_kem_keys);

    let bad_key = vec![0u8; 10];
    let mut failed_encap = ml_kem::ml_kem_1024_encapsulate_shared_secret(bad_key.as_ptr(), bad_key.len());
    assert_ne!(0, failed_encap.error_code);
    free_ml_kem_encapsulate_result(&mut failed_encap);

    free_slh_dsa_key_pair_result(std::ptr::null_mut());
    free_ml_dsa_key_pair_result(std::ptr::null_mut());
    free_ml_kem_key_pair_result(std::ptr::null_mut());
    free_ml_kem_encapsulate_result(std::ptr::null_mut());
}
