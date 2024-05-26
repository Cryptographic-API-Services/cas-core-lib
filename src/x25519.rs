use cas_lib::key_exchange::{cas_key_exchange::CASKeyExchange, x25519::X25519};
use std::ffi::c_uchar;
use x25519_dalek::{PublicKey, StaticSecret};

#[repr(C)]
pub struct x25519SecretPublicKeyResult {
    pub secret_key: *mut c_uchar,
    pub secret_key_length: usize,
    pub public_key: *mut c_uchar,
    pub public_key_length: usize,
}

#[repr(C)]
pub struct x25519SharedSecretResult {
    pub shared_secret: *mut c_uchar,
    pub shared_secret_length: usize,
}

#[no_mangle]
pub extern "C" fn generate_secret_and_public_key() -> x25519SecretPublicKeyResult {
    let result = <X25519 as CASKeyExchange>::generate_secret_and_public_key();
    let mut secret_key = result.secret_key;
    let mut public_key = result.public_key;
    let secret_key_capacity = secret_key.capacity();
    secret_key.reserve_exact(secret_key_capacity);
    let public_key_capacity = public_key.capacity();
    public_key.reserve_exact(public_key_capacity);
    let result = x25519SecretPublicKeyResult {
        secret_key: secret_key.as_mut_ptr(),
        secret_key_length: secret_key.len(),
        public_key: public_key.as_mut_ptr(),
        public_key_length: public_key.len(),
    };
    std::mem::forget(public_key);
    std::mem::forget(secret_key);
    result
}

#[no_mangle]
pub extern "C" fn generate_secret_and_public_key_threadpool() -> x25519SecretPublicKeyResult {
    let result = <X25519 as CASKeyExchange>::generate_secret_and_public_key_threadpool();
    let mut secret_key = result.secret_key;
    let mut public_key = result.public_key;
    let secret_key_capacity = secret_key.capacity();
    secret_key.reserve_exact(secret_key_capacity);
    let public_key_capacity = public_key.capacity();
    public_key.reserve_exact(public_key_capacity);
    let result = x25519SecretPublicKeyResult {
        secret_key: secret_key.as_mut_ptr(),
        secret_key_length: secret_key.len(),
        public_key: public_key.as_mut_ptr(),
        public_key_length: public_key.len(),
    };
    std::mem::forget(public_key);
    std::mem::forget(secret_key);
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
    let mut result =
        <X25519 as CASKeyExchange>::diffie_hellman(secret_key_slice, other_user_public_key);
    let capacity = result.capacity();
    result.reserve_exact(capacity);
    let return_result = x25519SharedSecretResult {
        shared_secret: result.as_mut_ptr(),
        shared_secret_length: result.len(),
    };
    std::mem::forget(result);
    return_result
}

#[no_mangle]
pub extern "C" fn diffie_hellman_threadpool(
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
    let mut result =
        <X25519 as CASKeyExchange>::diffie_hellman_threadpool(secret_key_slice, other_user_public_key);
    let capacity = result.capacity();
    result.reserve_exact(capacity);
    let return_result = x25519SharedSecretResult {
        shared_secret: result.as_mut_ptr(),
        shared_secret_length: result.len(),
    };
    std::mem::forget(result);
    return_result
}