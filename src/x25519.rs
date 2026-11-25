use cas_lib::key_exchange::{cas_key_exchange::CASKeyExchange, x25519::X25519};
use std::ffi::c_uchar;

use crate::helpers::{cas_error_code, export_bytes, free_bytes_field};

/// X25519 key pair from `generate_secret_and_public_key`.
///
/// The caller owns both buffers and must free them: pass the struct to
/// [`free_x25519_secret_public_key_result`], or call `free_bytes` once on each
/// pointer. `secret_key` is secret.
#[repr(C)]
pub struct x25519SecretPublicKeyResult {
    pub secret_key: *mut c_uchar,
    pub secret_key_length: usize,
    pub public_key: *mut c_uchar,
    pub public_key_length: usize,
}

/// X25519 shared secret from `diffie_hellman`.
///
/// The caller owns `shared_secret` (secret) and frees it with `free_bytes`. It
/// is null when `error_code` is non-zero.
#[repr(C)]
pub struct x25519SharedSecretResult {
    pub shared_secret: *mut c_uchar,
    pub shared_secret_length: usize,
    pub error_code: i32,
}

#[no_mangle]
pub extern "C" fn generate_secret_and_public_key() -> x25519SecretPublicKeyResult {
    let result = <X25519 as CASKeyExchange>::generate_secret_and_public_key();
    let secret_key = result.secret_key;
    let public_key = result.public_key;
    let result = x25519SecretPublicKeyResult {
        secret_key: export_bytes(&secret_key),
        secret_key_length: secret_key.len(),
        public_key: export_bytes(&public_key),
        public_key_length: public_key.len(),
    };
    result
}


#[test]
pub fn diffie_hellman_test() {
    let result1: x25519SecretPublicKeyResult = generate_secret_and_public_key();
    let result2: x25519SecretPublicKeyResult = generate_secret_and_public_key();
    let alice_secret_key: *const std::os::raw::c_uchar = result1.secret_key;
    let alice_public_key: *const std::os::raw::c_uchar = result1.public_key;
    let bob_public_key: *const std::os::raw::c_uchar = result2.public_key;
    let bob_secret_key: *const std::os::raw::c_uchar = result2.secret_key;
    let shared_secret_1 = diffie_hellman(
        alice_secret_key,
        result1.secret_key_length,
        bob_public_key,
        result2.public_key_length,
    );
    let shared_secret_2 = diffie_hellman(
        bob_secret_key,
        result2.secret_key_length,
        alice_public_key,
        result2.public_key_length,
    );

    let secret_key_1_slice: &[u8] = unsafe {
        std::slice::from_raw_parts(
            shared_secret_1.shared_secret,
            shared_secret_1.shared_secret_length,
        )
    };
    let secret_key_2_slice: &[u8] = unsafe {
        std::slice::from_raw_parts(
            shared_secret_2.shared_secret,
            shared_secret_2.shared_secret_length,
        )
    };
    assert_eq!(true, secret_key_1_slice.eq(secret_key_2_slice));
}

#[no_mangle]
pub extern "C" fn diffie_hellman(
    secret_key: *const c_uchar,
    secret_key_length: usize,
    other_user_public_key: *const c_uchar,
    other_user_public_key_length: usize,
) -> x25519SharedSecretResult {
    let secret_key_slice =
        unsafe { std::slice::from_raw_parts(secret_key, secret_key_length) }.to_vec();
    let other_user_public_key =
        unsafe { std::slice::from_raw_parts(other_user_public_key, other_user_public_key_length) }
            .to_vec();
    match <X25519 as CASKeyExchange>::diffie_hellman(secret_key_slice, other_user_public_key) {
        Ok(result) => {
            let return_result = x25519SharedSecretResult {
                shared_secret: export_bytes(&result),
                shared_secret_length: result.len(),
                error_code: 0,
            };
            return_result
        }
        Err(e) => x25519SharedSecretResult {
            shared_secret: std::ptr::null_mut(),
            shared_secret_length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

/// Frees both buffers of an [`x25519SecretPublicKeyResult`] and nulls its
/// fields, so a second call is harmless. A null `result` is ignored.
#[no_mangle]
pub extern "C" fn free_x25519_secret_public_key_result(result: *mut x25519SecretPublicKeyResult) {
    let Some(result) = (unsafe { result.as_mut() }) else { return };
    free_bytes_field(&mut result.secret_key, &mut result.secret_key_length);
    free_bytes_field(&mut result.public_key, &mut result.public_key_length);
}

#[test]
fn free_x25519_results_test() {
    let mut alice = generate_secret_and_public_key();
    let mut bob = generate_secret_and_public_key();
    let shared_secret = diffie_hellman(
        alice.secret_key,
        alice.secret_key_length,
        bob.public_key,
        bob.public_key_length,
    );
    assert_eq!(0, shared_secret.error_code);
    crate::helpers::free_bytes(shared_secret.shared_secret);

    free_x25519_secret_public_key_result(&mut alice);
    assert!(alice.secret_key.is_null() && alice.public_key.is_null());
    assert_eq!(0, alice.secret_key_length + alice.public_key_length);
    free_x25519_secret_public_key_result(&mut alice);
    free_x25519_secret_public_key_result(&mut bob);
    free_x25519_secret_public_key_result(std::ptr::null_mut());
}

#[test]
pub fn diffie_hellman_rejects_low_order_public_keys_test() {
    let invalid_key = cas_error_code(&cas_lib::error::CasError::InvalidKey);
    let keys = generate_secret_and_public_key();
    // Low-order points from RFC 7748 / Wycheproof: each forces an all-zero
    // shared secret, so the exchange is refused (#98).
    let mut low_order_public_keys: Vec<[u8; 32]> = vec![[0u8; 32]];
    let mut one = [0u8; 32];
    one[0] = 1;
    low_order_public_keys.push(one);
    low_order_public_keys.push([
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
        0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
    ]);
    for public_key in low_order_public_keys {
        let result = diffie_hellman(keys.secret_key, keys.secret_key_length, public_key.as_ptr(), public_key.len());
        assert!(result.shared_secret.is_null());
        assert_eq!(0, result.shared_secret_length);
        assert_eq!(invalid_key, result.error_code);
    }
}
