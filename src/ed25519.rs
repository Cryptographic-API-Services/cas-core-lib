use cas_lib::signatures::ed25519::{ed25519_sign_with_key_pair, ed25519_sign_with_key_pair_threadpool, ed25519_verify_with_key_pair, ed25519_verify_with_key_pair_threadpool, ed25519_verify_with_public_key, ed25519_verify_with_public_key_threadpool, get_ed25519_key_pair, get_ed25519_key_pair_threadpool};
use libc::{c_uchar, printf};

#[repr(C)]
pub struct Ed25519KeyPairBytesResult {
    key_pair: *mut u8,
    length: usize,
}

#[repr(C)]
pub struct Ed25519ByteSignatureResult {
    pub signature_byte_ptr: *mut u8,
    pub signature_length: usize,
    pub public_key: *mut u8,
    pub public_key_length: usize,
}

#[no_mangle]
pub extern "C" fn get_ed25519_key_pair_bytes() -> Ed25519KeyPairBytesResult {
    let keypair = get_ed25519_key_pair();
    let len = keypair.len();
    let key_pair_ptr = unsafe {
        let ptr = libc::malloc(len) as *mut u8;
        std::ptr::copy_nonoverlapping(keypair.as_ptr(), ptr, len);
        ptr
    };
    let result = Ed25519KeyPairBytesResult {
        length: keypair.len(),
        key_pair: key_pair_ptr,
    };
    result
}

#[no_mangle]
pub extern "C" fn get_ed25519_key_pair_bytes_threadpool() -> Ed25519KeyPairBytesResult {
    let keypair = get_ed25519_key_pair_threadpool();
    let len = keypair.len();
    let key_pair_ptr = unsafe {
        let ptr = libc::malloc(len) as *mut u8;
        std::ptr::copy_nonoverlapping(keypair.as_ptr(), ptr, len);
        ptr
    };
    let result = Ed25519KeyPairBytesResult {
        length: keypair.len(),
        key_pair: key_pair_ptr,
    };
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
        assert!(key_pair_length == 32, "Key pair must be 32 bytes");
        let slice = std::slice::from_raw_parts(key_pair, key_pair_length);
        let mut array = [0u8; 32];
        array.copy_from_slice(slice);
        array
    };
    let message_to_sign_slice = unsafe {
        assert!(!message_to_sign.is_null());
        std::slice::from_raw_parts(message_to_sign, message_to_sign_length)
    };
    let result = ed25519_sign_with_key_pair(key_pair_slice, message_to_sign_slice);
    let public_key = result.public_key;
    let signature = result.signature;
    let public_key_pointer = unsafe {
        let ptr = libc::malloc(public_key.len()) as *mut u8;
        std::ptr::copy_nonoverlapping(public_key.as_ptr(), ptr, public_key.len());
        ptr
    };
    let signature_pointer = unsafe {
        let ptr = libc::malloc(signature.len()) as *mut u8;
        std::ptr::copy_nonoverlapping(signature.as_ptr(), ptr, signature.len());
        ptr
    };
    let result = Ed25519ByteSignatureResult {
        signature_byte_ptr: signature_pointer,
        signature_length: signature.len(),
        public_key: public_key_pointer,
        public_key_length: public_key.len(),
    };
    result
}

#[no_mangle]
pub extern "C" fn sign_with_key_pair_bytes_threadpool(
    key_pair: *const c_uchar,
    key_pair_length: usize,
    message_to_sign: *const c_uchar,
    message_to_sign_length: usize,
) -> Ed25519ByteSignatureResult {
    let key_pair_slice = unsafe {
        assert!(!key_pair.is_null());
        assert!(key_pair_length == 32, "Key pair must be 32 bytes in length");
        let slice = std::slice::from_raw_parts(key_pair, key_pair_length);
        let mut array = [0u8; 32];
        array.copy_from_slice(slice);
        array
    };
    let message_to_sign_slice = unsafe {
        assert!(!message_to_sign.is_null());
        std::slice::from_raw_parts(message_to_sign, message_to_sign_length)
    };
    let result = ed25519_sign_with_key_pair_threadpool(key_pair_slice, message_to_sign_slice);
    let public_key = result.public_key;
    let signature = result.signature;
    let public_key_pointer = unsafe {
        let ptr = libc::malloc(public_key.len()) as *mut u8;
        std::ptr::copy_nonoverlapping(public_key.as_ptr(), ptr, public_key.len());
        ptr
    };
    let signature_pointer = unsafe {
        let ptr = libc::malloc(signature.len()) as *mut u8;
        std::ptr::copy_nonoverlapping(signature.as_ptr(), ptr, signature.len());
        ptr
    };
    let result = Ed25519ByteSignatureResult {
        signature_byte_ptr: signature_pointer,
        signature_length: signature.len(),
        public_key: public_key_pointer,
        public_key_length: public_key.len(),
    };
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
        assert!(key_pair_length == 32, "Key pair length must be 32 bytes");
        let slice = std::slice::from_raw_parts(key_pair, key_pair_length);
        let mut array = [0u8; 32];
        array.copy_from_slice(slice);
        array
    };
    let signature_slice = unsafe {
        assert!(!signature.is_null());
        assert!(signature_length == 64, "Key pair length must be 64 bytes");
        let slice = std::slice::from_raw_parts(signature, signature_length);
        let mut array = [0u8; 64];
        array.copy_from_slice(slice);
        array
    };
    let message_slice = unsafe {
        assert!(!message.is_null());
        std::slice::from_raw_parts(message, message_length)
    };
    return ed25519_verify_with_key_pair(key_pair_slice, signature_slice, message_slice);
}

#[no_mangle]
pub extern "C" fn verify_with_key_pair_bytes_threadpool(
    key_pair: *const c_uchar,
    key_pair_length: usize,
    signature: *const c_uchar,
    signature_length: usize,
    message: *const c_uchar,
    message_length: usize,
) -> bool {
    let key_pair_slice: [u8; 32] = unsafe {
        assert!(!key_pair.is_null());
        assert!(key_pair_length == 32, "Key pair length must be 32 bytes");
        let slice = std::slice::from_raw_parts(key_pair, key_pair_length);
        let mut array = [0u8; 32];
        array.copy_from_slice(slice);
        array
    };
    let signature_slice = unsafe {
        assert!(!signature.is_null());
        assert!(signature_length == 64, "Signature length must be 64 bytes");
        let slice = std::slice::from_raw_parts(signature, signature_length);
        let mut array = [0u8; 64];
        array.copy_from_slice(slice);
        array
    };
    let message_slice = unsafe {
        assert!(!message.is_null());
        std::slice::from_raw_parts(message, message_length)
    };
    return ed25519_verify_with_key_pair_threadpool(key_pair_slice, signature_slice, message_slice);
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
    let public_key_slice: [u8; 32] = unsafe {
        assert!(!public_key.is_null());
        assert!(public_key_length == 32);
        let slice = std::slice::from_raw_parts(public_key, public_key_length);
        let mut array = [0u8; 32];
        array.copy_from_slice(slice);
        array
    };
    let signature_slice: [u8; 64] = unsafe {
        assert!(!signature.is_null());
        assert!(signature_length == 64, "Signature slice must be 64 bytes");
        let slice = std::slice::from_raw_parts(signature, signature_length);
        let mut array = [0u8; 64];
        array.copy_from_slice(slice);
        array
    };
    let message_slice = unsafe {
        assert!(!message.is_null());
        std::slice::from_raw_parts(message, message_length)
    };
    return ed25519_verify_with_public_key(public_key_slice, signature_slice, message_slice);
}

#[no_mangle]
pub extern "C" fn verify_with_public_key_bytes_threadpool(
    public_key: *const c_uchar,
    public_key_length: usize,
    signature: *const c_uchar,
    signature_length: usize,
    message: *const c_uchar,
    message_length: usize,
) -> bool {
    let public_key_slice: [u8; 32] = unsafe {
        assert!(!public_key.is_null());
        assert!(public_key_length == 32, "Public key length must be 64 bytes");
        let slice = std::slice::from_raw_parts(public_key, public_key_length);
        let mut array = [0u8; 32];
        array.copy_from_slice(slice);
        array
    };
    let signature_slice: [u8; 64] = unsafe {
        assert!(!signature.is_null());
        assert!(signature_length == 64, "Signature Slice must be 32 bytes");
        let slice = std::slice::from_raw_parts(signature, signature_length);
        let mut array = [0u8; 64];
        array.copy_from_slice(slice);
        array
    };
    let message_slice = unsafe {
        assert!(!message.is_null());
        std::slice::from_raw_parts(message, message_length)
    };
    return ed25519_verify_with_public_key_threadpool(public_key_slice, signature_slice, message_slice);
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
