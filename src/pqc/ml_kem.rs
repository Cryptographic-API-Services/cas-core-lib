use cas_lib::pqc::ml_kem::{ml_kem_1024_decapsulate, ml_kem_1024_encapsulate, ml_kem_1024_generate};
use crate::pqc::types::{MlKemDecapsulateResult, MlKemEncapsulateResult, MlKemKeyPairResult};
use crate::helpers::cas_error_code;

#[no_mangle]
pub extern "C" fn ml_kem_1024_generate_key_pair() -> MlKemKeyPairResult {
    let key_pair: cas_lib::pqc::cas_pqc::MlKemKeyPair = ml_kem_1024_generate();
    let result = MlKemKeyPairResult {
        secret_key_ptr: key_pair.secret_key.as_ptr(),
        secret_key_length: key_pair.secret_key.len(),
        public_key_ptr: key_pair.public_key.as_ptr(),
        public_key_length: key_pair.public_key.len(),
    };
    std::mem::forget(key_pair.secret_key);
    std::mem::forget(key_pair.public_key);
    result
}

#[no_mangle]
pub extern "C" fn ml_kem_1024_encapsulate_shared_secret(
    public_key: *const u8,
    public_key_length: usize,
) -> MlKemEncapsulateResult {
    let public_key_slice = unsafe {
        assert!(!public_key.is_null());
        std::slice::from_raw_parts(public_key, public_key_length)
    }
    .to_vec();
    match ml_kem_1024_encapsulate(public_key_slice) {
        Ok(encap) => {
            let result = MlKemEncapsulateResult {
                ciphertext_ptr: encap.ciphertext.as_ptr(),
                ciphertext_length: encap.ciphertext.len(),
                shared_secret_ptr: encap.shared_secret.as_ptr(),
                shared_secret_length: encap.shared_secret.len(),
                error_code: 0,
            };
            std::mem::forget(encap.ciphertext);
            std::mem::forget(encap.shared_secret);
            result
        }
        Err(e) => MlKemEncapsulateResult {
            ciphertext_ptr: std::ptr::null(),
            ciphertext_length: 0,
            shared_secret_ptr: std::ptr::null(),
            shared_secret_length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

#[no_mangle]
pub extern "C" fn ml_kem_1024_decapsulate_shared_secret(
    secret_key: *const u8,
    secret_key_length: usize,
    ciphertext: *const u8,
    ciphertext_length: usize,
) -> MlKemDecapsulateResult {
    let secret_key_slice = unsafe {
        assert!(!secret_key.is_null());
        std::slice::from_raw_parts(secret_key, secret_key_length)
    }
    .to_vec();
    let ciphertext_slice = unsafe {
        assert!(!ciphertext.is_null());
        std::slice::from_raw_parts(ciphertext, ciphertext_length)
    }
    .to_vec();
    match ml_kem_1024_decapsulate(secret_key_slice, ciphertext_slice) {
        Ok(shared_secret) => {
            let result = MlKemDecapsulateResult {
                shared_secret_ptr: shared_secret.as_ptr(),
                shared_secret_length: shared_secret.len(),
                error_code: 0,
            };
            std::mem::forget(shared_secret);
            result
        }
        Err(e) => MlKemDecapsulateResult {
            shared_secret_ptr: std::ptr::null(),
            shared_secret_length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

#[test]
fn ml_kem_1024_encapsulate_decapsulate_test() {
    let key_pair = ml_kem_1024_generate_key_pair();
    let encap = ml_kem_1024_encapsulate_shared_secret(key_pair.public_key_ptr, key_pair.public_key_length);
    assert_eq!(0, encap.error_code);
    let decap = ml_kem_1024_decapsulate_shared_secret(
        key_pair.secret_key_ptr,
        key_pair.secret_key_length,
        encap.ciphertext_ptr,
        encap.ciphertext_length,
    );
    assert_eq!(0, decap.error_code);
    let sender_secret = unsafe { std::slice::from_raw_parts(encap.shared_secret_ptr, encap.shared_secret_length) };
    let receiver_secret = unsafe { std::slice::from_raw_parts(decap.shared_secret_ptr, decap.shared_secret_length) };
    assert_eq!(sender_secret, receiver_secret);
}

#[test]
fn ml_kem_1024_encapsulate_invalid_key_test() {
    let bad_key = vec![0u8; 10];
    let encap = ml_kem_1024_encapsulate_shared_secret(bad_key.as_ptr(), bad_key.len());
    assert_ne!(0, encap.error_code);
    assert!(encap.ciphertext_ptr.is_null());
    assert!(encap.shared_secret_ptr.is_null());
}

#[test]
fn ml_kem_1024_decapsulate_invalid_ciphertext_test() {
    let key_pair = ml_kem_1024_generate_key_pair();
    let bad_ciphertext = vec![0u8; 10];
    let decap = ml_kem_1024_decapsulate_shared_secret(
        key_pair.secret_key_ptr,
        key_pair.secret_key_length,
        bad_ciphertext.as_ptr(),
        bad_ciphertext.len(),
    );
    assert_ne!(0, decap.error_code);
    assert!(decap.shared_secret_ptr.is_null());
}
