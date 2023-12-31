use aes_gcm::{
    aead::{generic_array::GenericArray, AeadMut, OsRng},
    Aes128Gcm, Aes256Gcm, KeyInit, Nonce,
};
use rand_07::AsByteSliceMut;
use std::ffi::{c_char, c_uchar, CStr, CString};

#[repr(C)]
pub struct AesBytesEncrypt {
    pub ciphertext: *mut c_uchar,
    pub length: usize,
}

#[repr(C)]
pub struct AesBytesDecrypt {
    pub plaintext: *mut c_uchar,
    pub length: usize,
}

#[no_mangle]
pub extern "C" fn aes_256_key() -> *mut c_char {
    return CString::new(base64::encode(Aes256Gcm::generate_key(&mut OsRng)))
        .unwrap()
        .into_raw();
}

#[no_mangle]
pub extern "C" fn aes_128_key() -> *mut c_char {
    return CString::new(base64::encode(Aes128Gcm::generate_key(&mut OsRng)))
        .unwrap()
        .into_raw();
}

#[no_mangle]
pub extern "C" fn aes_128_encrypt_bytes_with_key(
    nonce_key: *const c_char,
    key: *const c_char,
    to_encrypt: *const c_uchar,
    to_encrypt_length: usize,
) -> AesBytesEncrypt {
    let nonce_string_key = unsafe {
        assert!(!nonce_key.is_null());
        CStr::from_ptr(nonce_key)
    }
    .to_str()
    .unwrap()
    .as_bytes();

    let key_string = unsafe {
        assert!(!key.is_null());
        CStr::from_ptr(key)
    }
    .to_str()
    .unwrap();
    let to_encrypt_slice: &[u8] =
        unsafe { std::slice::from_raw_parts(to_encrypt, to_encrypt_length) };
    let mut decoded_string_key = base64::decode(key_string).unwrap();
    let key = GenericArray::from_slice(decoded_string_key.as_byte_slice_mut());
    let mut cipher = Aes128Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_string_key); // 96-bits; unique per message
    let mut ciphertext: Vec<u8> = cipher.encrypt(nonce, to_encrypt_slice.as_ref()).unwrap();
    let capacity = ciphertext.capacity();
    ciphertext.reserve_exact(capacity);
    let result = AesBytesEncrypt {
        ciphertext: ciphertext.as_mut_ptr(),
        length: ciphertext.len(),
    };
    std::mem::forget(ciphertext);
    return result;
}

#[no_mangle]
pub extern "C" fn aes_256_encrypt_bytes_with_key(
    nonce_key: *const c_char,
    key: *const c_char,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
) -> AesBytesEncrypt {
    let nonce_string_key = unsafe {
        assert!(!nonce_key.is_null());
        CStr::from_ptr(nonce_key)
    }
    .to_str()
    .unwrap()
    .as_bytes();

    let key_string = unsafe {
        assert!(!key.is_null());
        CStr::from_ptr(key)
    }
    .to_str()
    .unwrap();
    let to_decrypt_slice = unsafe { std::slice::from_raw_parts(to_decrypt, to_decrypt_length) };
    let mut decoded_string_key = base64::decode(key_string).unwrap();
    let key = GenericArray::from_slice(decoded_string_key.as_byte_slice_mut());
    let mut cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_string_key); // 96-bits; unique per message
    let mut ciphertext = cipher.encrypt(nonce, to_decrypt_slice).unwrap();
    let capacity = ciphertext.capacity();
    ciphertext.reserve_exact(capacity);
    let result = AesBytesEncrypt {
        ciphertext: ciphertext.as_mut_ptr(),
        length: ciphertext.len(),
    };
    std::mem::forget(ciphertext);
    return result;
}

#[no_mangle]
pub extern "C" fn aes_128_decrypt_bytes_with_key(
    nonce_key: *const c_char,
    key: *const c_char,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
) -> AesBytesDecrypt {
    let nonce_string_key = unsafe {
        assert!(!nonce_key.is_null());
        CStr::from_ptr(nonce_key)
    }
    .to_str()
    .unwrap()
    .as_bytes();

    let key_string = unsafe {
        assert!(!key.is_null());
        CStr::from_ptr(key)
    }
    .to_str()
    .unwrap();
    let to_decrypt_slice = unsafe { std::slice::from_raw_parts(to_decrypt, to_decrypt_length) };
    let mut decoded_string_key = base64::decode(key_string).unwrap();
    let key = GenericArray::from_slice(decoded_string_key.as_byte_slice_mut());
    let mut cipher = Aes128Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_string_key); // 96-bits; unique per message
    let mut plaintext = cipher.decrypt(nonce, to_decrypt_slice).unwrap();
    let capacity = plaintext.capacity();
    plaintext.reserve_exact(capacity);
    let result = AesBytesDecrypt {
        plaintext: plaintext.as_mut_ptr(),
        length: plaintext.len(),
    };
    std::mem::forget(plaintext);
    return result;
}

#[no_mangle]
pub extern "C" fn aes_256_decrypt_bytes_with_key(
    nonce_key: *const c_char,
    key: *const c_char,
    to_decrypt: *const c_uchar,
    to_decrypt_length: usize,
) -> AesBytesDecrypt {
    let nonce_string_key = unsafe {
        assert!(!nonce_key.is_null());
        CStr::from_ptr(nonce_key)
    }
    .to_str()
    .unwrap()
    .as_bytes();

    let key_string = unsafe {
        assert!(!key.is_null());
        CStr::from_ptr(key)
    }
    .to_str()
    .unwrap();
    let to_decrypt_slice = unsafe { std::slice::from_raw_parts(to_decrypt, to_decrypt_length) };
    let mut decoded_string_key = base64::decode(key_string).unwrap();
    let key = GenericArray::from_slice(decoded_string_key.as_byte_slice_mut());
    let mut cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_string_key); // 96-bits; unique per message
    let mut plaintext = cipher.decrypt(nonce, to_decrypt_slice).unwrap();
    let capacity = plaintext.capacity();
    plaintext.reserve_exact(capacity);
    let result = AesBytesDecrypt {
        plaintext: plaintext.as_mut_ptr(),
        length: plaintext.len(),
    };
    std::mem::forget(plaintext);
    return result;
}