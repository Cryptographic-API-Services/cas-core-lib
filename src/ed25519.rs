extern crate ed25519_dalek;
extern crate rand;

use ed25519_dalek::Signer;
use ed25519_dalek::{Keypair, PublicKey, Signature, Verifier};
use libc::c_uchar;
use rand_07::rngs::OsRng;

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
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);
    let keypair_bytes = keypair.to_bytes();
    return unsafe {
        let size_of_result = std::mem::size_of_val(&keypair_bytes);
        let result_raw_ptr = libc::malloc(size_of_result) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(keypair_bytes.as_ptr(), result_raw_ptr, size_of_result);
        let result = Ed25519KeyPairBytesResult {
            length: size_of_result,
            key_pair: result_raw_ptr,
        };
        result
    };
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
    };
    let message_to_sign_slice = unsafe {
        assert!(!message_to_sign.is_null());
        std::slice::from_raw_parts(message_to_sign, message_to_sign_length)
    };
    let keypair = Keypair::from_bytes(key_pair_slice).unwrap();
    let signature = keypair.sign(&message_to_sign_slice);
    let signature_bytes = signature.to_bytes();
    let public_keypair_bytes = keypair.public.to_bytes();
    return unsafe {
        let size_of_signature = std::mem::size_of_val(&signature_bytes);
        let signature_raw_ptr = libc::malloc(size_of_signature) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(
            signature_bytes.as_ptr(),
            signature_raw_ptr,
            size_of_signature,
        );
        let size_of_public_key = std::mem::size_of_val(&public_keypair_bytes);
        let public_key_raw_ptr = libc::malloc(size_of_public_key) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(
            public_keypair_bytes.as_ptr(),
            public_key_raw_ptr,
            size_of_public_key,
        );
        let result = Ed25519ByteSignatureResult {
            signature_byte_ptr: signature_raw_ptr,
            signature_length: size_of_signature,
            public_key: public_key_raw_ptr,
            public_key_length: size_of_public_key,
        };
        result
    };
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
    };
    let signature_slice = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    };
    let message_slice = unsafe {
        assert!(!message.is_null());
        std::slice::from_raw_parts(message, message_length)
    };
    let keypair = Keypair::from_bytes(&key_pair_slice).unwrap();
    let public_key = keypair.public;
    let signature = Signature::from_bytes(&signature_slice).unwrap();
    return public_key.verify(&message_slice, &signature).is_ok();
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
    };
    let signature_slice = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    };
    let message_slice = unsafe {
        assert!(!message.is_null());
        std::slice::from_raw_parts(message, message_length)
    };
    let public_key_parsed = PublicKey::from_bytes(&public_key_slice).unwrap();
    let signature_parsed = Signature::from_bytes(&signature_slice).unwrap();
    return public_key_parsed
        .verify(&message_slice, &signature_parsed)
        .is_ok();
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
