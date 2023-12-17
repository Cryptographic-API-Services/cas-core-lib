extern crate ed25519_dalek;
extern crate rand;

use ed25519_dalek::Signer;
use ed25519_dalek::{Keypair, PublicKey, Signature, Verifier};
use libc::c_uchar;
use rand_07::rngs::OsRng;
use std::ffi::{c_char, CStr, CString};

#[repr(C)]
pub struct Ed25519SignatureResult {
    pub signature: *mut c_char,
    pub public_key: *mut c_char,
}

#[no_mangle]
pub extern "C" fn get_ed25519_key_pair() -> *mut c_char {
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    return CString::new(base64::encode(keypair.to_bytes()))
        .unwrap()
        .into_raw();
}

#[test]
fn get_ed25519_key_pair_test() {
    let key_pair = get_ed25519_key_pair();
    assert_eq!(false, key_pair.is_null());
}

#[no_mangle]
pub extern "C" fn get_ed25519_key_pair_bytes() -> *mut c_uchar {
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);
    let keypair_bytes = keypair.to_bytes();
    return unsafe {
        let size_of_result = std::mem::size_of_val(&keypair_bytes);
        let result_raw_ptr = libc::malloc(size_of_result) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(keypair_bytes.as_ptr(), result_raw_ptr, size_of_result);  
        result_raw_ptr
    };
}

#[test]
fn get_ed25519_key_pair_bytes_test() {
    let key_pair_bytes = get_ed25519_key_pair_bytes();
    assert_eq!(false, key_pair_bytes.is_null());
}

#[no_mangle]
pub extern "C" fn sign_with_key_pair(
    key_pair: *const c_char,
    message_to_sign: *const c_char,
) -> Ed25519SignatureResult {
    let key_pair_string = unsafe {
        assert!(!key_pair.is_null());
        CStr::from_ptr(key_pair)
    }
    .to_str()
    .unwrap();
    let message_to_sign_bytes = unsafe {
        assert!(!message_to_sign.is_null());
        CStr::from_ptr(message_to_sign)
    }
    .to_str()
    .unwrap()
    .as_bytes();
    let key_pair_vec = base64::decode(key_pair_string).unwrap();
    let keypair = Keypair::from_bytes(&key_pair_vec).unwrap();
    let signature = keypair.sign(&message_to_sign_bytes);
    return Ed25519SignatureResult {
        signature: CString::new(base64::encode(signature.to_bytes()))
            .unwrap()
            .into_raw(),
        public_key: CString::new(base64::encode(keypair.public.to_bytes()))
            .unwrap()
            .into_raw(),
    };
}

#[test]
fn sign_with_key_pair_test() {
    let key_pair = get_ed25519_key_pair();
    let message = "SignThisMessageWithED25519Dalek".as_bytes();
    let message_to_sign = CString::new(base64::encode(message)).unwrap().into_raw();
    let result: Ed25519SignatureResult = sign_with_key_pair(key_pair, message_to_sign);
    assert_ne!(message_to_sign, result.signature);
}

#[no_mangle]
pub extern "C" fn verify_with_key_pair(
    key_pair: *const c_char,
    signature: *const c_char,
    message: *const c_char,
) -> bool {
    let key_pair_string = unsafe {
        assert!(!key_pair.is_null());
        CStr::from_ptr(key_pair)
    }
    .to_str()
    .unwrap();
    let signature_bytes = unsafe {
        assert!(!signature.is_null());
        CStr::from_ptr(signature)
    }
    .to_str()
    .unwrap()
    .as_bytes();
    let message = unsafe {
        assert!(!message.is_null());
        CStr::from_ptr(message)
    }
    .to_str()
    .unwrap()
    .as_bytes();
    let key_pair_vec = base64::decode(key_pair_string).unwrap();
    let signature_vec = base64::decode(signature_bytes).unwrap();
    let keypair = Keypair::from_bytes(&key_pair_vec).unwrap();
    let public_key = keypair.public;
    let signature = Signature::from_bytes(&signature_vec).unwrap();
    return public_key.verify(&message, &signature).is_ok();
}

#[test]
fn verify_with_key_pair_test() {
    let key_pair = get_ed25519_key_pair();
    let message = "SignThisMessageWithED25519Dalek".as_bytes();
    let message_to_sign = CString::new(base64::encode(message)).unwrap().into_raw();
    let result: Ed25519SignatureResult = sign_with_key_pair(key_pair, message_to_sign);
    let is_valid = verify_with_key_pair(key_pair, result.signature, message_to_sign);
    assert_eq!(true, is_valid);
}

#[no_mangle]
pub extern "C" fn verify_with_public_key(
    public_key: *const c_char,
    signature: *const c_char,
    message: *const c_char,
) -> bool {
    let public_key_string = unsafe {
        assert!(!public_key.is_null());
        CStr::from_ptr(public_key)
    }
    .to_str()
    .unwrap();
    let signature_bytes = unsafe {
        assert!(!signature.is_null());
        CStr::from_ptr(signature)
    }
    .to_str()
    .unwrap()
    .as_bytes();
    let message_string = unsafe {
        assert!(!message.is_null());
        CStr::from_ptr(message)
    }
    .to_str()
    .unwrap()
    .as_bytes();
    let public_key_vec = base64::decode(public_key_string).unwrap();
    let public_key = PublicKey::from_bytes(&public_key_vec).unwrap();
    let signature_vec = base64::decode(signature_bytes).unwrap();
    let signature = Signature::from_bytes(&signature_vec).unwrap();
    return public_key.verify(&message_string, &signature).is_ok();
}

#[test]
fn verify_with_public_key_test() {
    let key_pair = get_ed25519_key_pair();
    let message = "SignThisMessageWithED25519Dalek".as_bytes();
    let message_to_sign = CString::new(base64::encode(message)).unwrap().into_raw();
    let result: Ed25519SignatureResult = sign_with_key_pair(key_pair, message_to_sign);
    let is_valid = verify_with_public_key(result.public_key, result.signature, message_to_sign);
    assert_eq!(true, is_valid);
}