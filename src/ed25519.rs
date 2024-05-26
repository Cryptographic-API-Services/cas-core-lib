use cas_lib::signatures::ed25519::{ed25519_sign_with_key_pair, ed25519_verify_with_key_pair, ed25519_verify_with_public_key, get_ed25519_key_pair};
use libc::c_uchar;

#[repr(C)]
pub struct Ed25519KeyPairBytesResult {
    key_pair: *mut c_uchar,
    length: usize,
}

#[repr(C)]
pub struct Ed25519ByteSignatureResult {
    pub signature_byte_ptr: *mut c_uchar,
    pub signature_length: usize,
    pub public_key: *mut c_uchar,
    pub public_key_length: usize,
}

#[no_mangle]
pub extern "C" fn get_ed25519_key_pair_bytes() -> Ed25519KeyPairBytesResult {
    let mut keypair = get_ed25519_key_pair();
    let capacity = keypair.capacity();
    keypair.reserve_exact(capacity);
    let result = Ed25519KeyPairBytesResult {
        length: keypair.len(),
        key_pair: keypair.as_mut_ptr(),
    };
    std::mem::forget(keypair);
    result
}

#[test]
fn get_ed25519_key_pair_bytes_test() {
    let key_pair_result = get_ed25519_key_pair_bytes();
    assert_eq!(false, key_pair_result.key_pair.is_null());
    assert_eq!(true, key_pair_result.length > 0);
}

#[no_mangle]
pub extern "C" fn sign_with_key_pair_bytes(
    key_pair: *const c_uchar,
    key_pair_length: usize,
    message_to_sign: *const c_uchar,
    message_to_sign_length: usize,
) -> Ed25519ByteSignatureResult {
    let key_pair_slice = unsafe {
        assert!(!key_pair.is_null());
        std::slice::from_raw_parts(key_pair, key_pair_length)
    }
    .to_vec();
    let message_to_sign_slice = unsafe {
        assert!(!message_to_sign.is_null());
        std::slice::from_raw_parts(message_to_sign, message_to_sign_length)
    }
    .to_vec();
    let result = ed25519_sign_with_key_pair(key_pair_slice, message_to_sign_slice);
    let mut public_key = result.public_key;
    let public_key_capacity = public_key.capacity();
    public_key.reserve_exact(public_key_capacity);
    let mut signature = result.signature;
    let siganture_capacity = signature.capacity();
    signature.reserve_exact(siganture_capacity);
    let result = Ed25519ByteSignatureResult {
        signature_byte_ptr: signature.as_mut_ptr(),
        signature_length: signature.len(),
        public_key: public_key.as_mut_ptr(),
        public_key_length: public_key.len(),
    };
    std::mem::forget(public_key);
    std::mem::forget(signature);
    result
}

#[test]
fn sign_with_key_pair_bytes_test() {
    let key_pair_result: Ed25519KeyPairBytesResult = get_ed25519_key_pair_bytes();
    let message: &str = "ThisIsAMessageToSignWithED25519Dalek";
    let message_byte: &[u8] = message.as_bytes();
    let signature_result: Ed25519ByteSignatureResult = sign_with_key_pair_bytes(
        key_pair_result.key_pair,
        key_pair_result.length,
        message_byte.as_ptr(),
        message_byte.len(),
    );
    assert_eq!(false, signature_result.public_key.is_null());
    assert_eq!(true, signature_result.public_key_length > 0);
    assert_eq!(false, signature_result.signature_byte_ptr.is_null());
    assert_eq!(true, signature_result.signature_length > 0);
}

#[no_mangle]
pub extern "C" fn verify_with_key_pair_bytes(
    key_pair: *const c_uchar,
    key_pair_length: usize,
    signature: *const c_uchar,
    signature_length: usize,
    message: *const c_uchar,
    message_length: usize,
) -> bool {
    let key_pair_slice = unsafe {
        assert!(!key_pair.is_null());
        std::slice::from_raw_parts(key_pair, key_pair_length)
    }.to_vec();
    let signature_slice = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }.to_vec();
    let message_slice = unsafe {
        assert!(!message.is_null());
        std::slice::from_raw_parts(message, message_length)
    }.to_vec();
    return ed25519_verify_with_key_pair(key_pair_slice, signature_slice, message_slice);
}

#[test]
fn verify_with_key_pair_bytes_test() {
    let key_pair = get_ed25519_key_pair_bytes();
    let message = "SignThisMessageWithED25519Dalek".as_bytes();
    let sign_result: Ed25519ByteSignatureResult = sign_with_key_pair_bytes(
        key_pair.key_pair,
        key_pair.length,
        message.as_ptr(),
        message.len(),
    );
    let is_valid = verify_with_key_pair_bytes(
        key_pair.key_pair,
        key_pair.length,
        sign_result.signature_byte_ptr,
        sign_result.signature_length,
        message.as_ptr(),
        message.len(),
    );
    assert_eq!(true, is_valid);
}

#[no_mangle]
pub extern "C" fn verify_with_public_key_bytes(
    public_key: *const c_uchar,
    public_key_length: usize,
    signature: *const c_uchar,
    signature_length: usize,
    message: *const c_uchar,
    message_length: usize,
) -> bool {
    let public_key_slice = unsafe {
        assert!(!public_key.is_null());
        std::slice::from_raw_parts(public_key, public_key_length)
    }.to_vec();
    let signature_slice = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }.to_vec();
    let message_slice = unsafe {
        assert!(!message.is_null());
        std::slice::from_raw_parts(message, message_length)
    }.to_vec();
    return ed25519_verify_with_public_key(public_key_slice, signature_slice, message_slice);
}

#[test]
fn verify_with_public_key_bytes_test() {
    let key_pair = get_ed25519_key_pair_bytes();
    let message = "SignThisMessageWithED25519Dalek".as_bytes();
    let signature_result: Ed25519ByteSignatureResult = sign_with_key_pair_bytes(
        key_pair.key_pair,
        key_pair.length,
        message.as_ptr(),
        message.len(),
    );
    let is_valid: bool = verify_with_public_key_bytes(
        signature_result.public_key,
        signature_result.public_key_length,
        signature_result.signature_byte_ptr,
        signature_result.signature_length,
        message.as_ptr(),
        message.len(),
    );
    assert_eq!(true, is_valid);
}
