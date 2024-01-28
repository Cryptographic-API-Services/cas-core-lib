use rsa::rand_core::OsRng;
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
    let secret_key = StaticSecret::random_from_rng(&mut OsRng);
    let public_key = PublicKey::from(&secret_key);
    let secret_key_bytes = secret_key.to_bytes();
    let public_key_bytes = public_key.to_bytes();
    return unsafe {
        let size_secret_key = std::mem::size_of_val(&secret_key_bytes);
        let secret_key_ptr = libc::malloc(size_secret_key) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(secret_key_bytes.as_ptr(), secret_key_ptr, size_secret_key);

        let size_public_key = std::mem::size_of_val(&public_key_bytes);
        let public_key_ptr = libc::malloc(size_public_key) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(public_key_bytes.as_ptr(), public_key_ptr, size_public_key);

        let result = x25519SecretPublicKeyResult {
            secret_key: secret_key_ptr,
            secret_key_length: size_secret_key,
            public_key: public_key_ptr,
            public_key_length: size_public_key,
        };
        result
    };
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
    
    let secret_key_1_slice: &[u8] =
        unsafe { std::slice::from_raw_parts(shared_secret_1.shared_secret, shared_secret_1.shared_secret_length) };
    let secret_key_2_slice: &[u8] =
        unsafe { std::slice::from_raw_parts(shared_secret_2.shared_secret, shared_secret_2.shared_secret_length) };
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
        unsafe { std::slice::from_raw_parts(secret_key, secret_key_length) };
    let other_user_public_key =
        unsafe { std::slice::from_raw_parts(other_user_public_key, other_user_public_key_length) };

    let mut secret_key_array: [u8; 32] = Default::default();
    secret_key_array.copy_from_slice(&secret_key_slice);

    let mut other_user_public_key_array: [u8; 32] = Default::default();
    other_user_public_key_array.copy_from_slice(&other_user_public_key);

    let secret_key = StaticSecret::from(secret_key_array);
    let public_key = PublicKey::from(other_user_public_key_array);
    let shared_secret = secret_key.diffie_hellman(&public_key);
    let shared_secret_bytes = shared_secret.as_bytes();
    return unsafe {
        let size_shared_secret = std::mem::size_of_val(&shared_secret_bytes);
        let shared_secret_ptr = libc::malloc(size_shared_secret) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(
            shared_secret_bytes.as_ptr(),
            shared_secret_ptr,
            size_shared_secret,
        );
        let result = x25519SharedSecretResult {
            shared_secret: shared_secret_ptr,
            shared_secret_length: size_shared_secret,
        };
        result
    };
}
