use std::ffi::{c_char, c_uchar, CStr, CString};
use std::sync::mpsc;

use rand::rngs::OsRng;
use rsa::RsaPrivateKey;
use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    PaddingScheme, PublicKey, RsaPublicKey,
};

mod types;
use self::types::{RsaDecryptBytesResult, RsaEncryptBytesResult, RsaKeyGenerationThreadPool, RsaKeyPair, RsaSignBytesResults};

#[no_mangle]
pub extern "C" fn rsa_encrypt_bytes(
    pub_key: *const c_char,
    data_to_encrypt: *const c_uchar,
    data_to_encrypt_length: usize,
) -> RsaEncryptBytesResult {
    let pub_key_string = unsafe {
        assert!(!pub_key.is_null());
        CStr::from_ptr(pub_key)
    }
    .to_str()
    .unwrap();
    let data_to_encrypt_slice = unsafe {
        assert!(!data_to_encrypt.is_null());
        std::slice::from_raw_parts(data_to_encrypt, data_to_encrypt_length)
    };
    let public_key = RsaPublicKey::from_pkcs1_pem(pub_key_string).unwrap();
    let mut rng = rand::thread_rng();
    let mut encrypted_bytes = public_key
        .encrypt(
            &mut rng,
            PaddingScheme::new_pkcs1v15_encrypt(),
            data_to_encrypt_slice,
        )
        .unwrap();
    let capacity = encrypted_bytes.capacity();
    encrypted_bytes.reserve_exact(capacity);
    let result = RsaEncryptBytesResult {
        encrypted_result_ptr: encrypted_bytes.as_mut_ptr(),
        length: encrypted_bytes.len(),
    };
    std::mem::forget(encrypted_bytes);
    return result;
}

#[no_mangle]
pub extern "C" fn rsa_encrypt_bytes_threadpool(
    pub_key: *const c_char,
    data_to_encrypt: *const c_uchar,
    data_to_encrypt_length: usize,
) -> RsaEncryptBytesResult {
    let pub_key_string = unsafe {
        assert!(!pub_key.is_null());
        CStr::from_ptr(pub_key)
    }
    .to_str()
    .unwrap();
    let data_to_encrypt_slice = unsafe {
        assert!(!data_to_encrypt.is_null());
        std::slice::from_raw_parts(data_to_encrypt, data_to_encrypt_length)
    };
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let public_key = RsaPublicKey::from_pkcs1_pem(pub_key_string).unwrap();
        let mut rng = rand::thread_rng();
        let encrypted_bytes = public_key
            .encrypt(
                &mut rng,
                PaddingScheme::new_pkcs1v15_encrypt(),
                data_to_encrypt_slice,
            )
            .unwrap();
        sender.send(encrypted_bytes);
    });
    let mut encrypted_bytes = receiver.recv().unwrap();
    let capacity = encrypted_bytes.capacity();
    encrypted_bytes.reserve_exact(capacity);
    let result = RsaEncryptBytesResult {
        encrypted_result_ptr: encrypted_bytes.as_mut_ptr(),
        length: encrypted_bytes.len(),
    };
    std::mem::forget(encrypted_bytes);
    return result;
}

#[no_mangle]
pub extern "C" fn rsa_decrypt_bytes(
    priv_key: *const c_char,
    data_to_decrypt: *const c_uchar,
    data_to_decrypt_length: usize,
) -> RsaDecryptBytesResult {
    let priv_key_string = unsafe {
        assert!(!priv_key.is_null());
        CStr::from_ptr(priv_key)
    }
    .to_str()
    .unwrap();

    let data_to_decrypt_slice: &[u8] = unsafe {
        assert!(!data_to_decrypt.is_null());
        std::slice::from_raw_parts(data_to_decrypt, data_to_decrypt_length)
    };

    let private_key = RsaPrivateKey::from_pkcs8_pem(priv_key_string).unwrap();
    let mut decrypted_bytes = private_key
        .decrypt(
            PaddingScheme::new_pkcs1v15_encrypt(),
            &data_to_decrypt_slice,
        )
        .expect("failed to decrypt");
    let capacity = decrypted_bytes.capacity();
    decrypted_bytes.reserve_exact(capacity);
    let result = RsaDecryptBytesResult {
        decrypted_result_ptr: decrypted_bytes.as_mut_ptr(),
        length: decrypted_bytes.len(),
    };
    std::mem::forget(decrypted_bytes);
    return result;
}

#[no_mangle]
pub extern "C" fn rsa_decrypt_bytes_threadpool(
    priv_key: *const c_char,
    data_to_decrypt: *const c_uchar,
    data_to_decrypt_length: usize,
) -> RsaDecryptBytesResult {
    let priv_key_string = unsafe {
        assert!(!priv_key.is_null());
        CStr::from_ptr(priv_key)
    }
    .to_str()
    .unwrap();

    let data_to_decrypt_slice: &[u8] = unsafe {
        assert!(!data_to_decrypt.is_null());
        std::slice::from_raw_parts(data_to_decrypt, data_to_decrypt_length)
    };
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let private_key = RsaPrivateKey::from_pkcs8_pem(priv_key_string).unwrap();
        let decrypted_bytes = private_key
            .decrypt(
                PaddingScheme::new_pkcs1v15_encrypt(),
                &data_to_decrypt_slice,
            )
            .expect("failed to decrypt");
        sender.send(decrypted_bytes);
    });
    let mut decrypted_bytes = receiver.recv().unwrap();
    let capacity = decrypted_bytes.capacity();
    decrypted_bytes.reserve_exact(capacity);
    let result = RsaDecryptBytesResult {
        decrypted_result_ptr: decrypted_bytes.as_mut_ptr(),
        length: decrypted_bytes.len(),
    };
    std::mem::forget(decrypted_bytes);
    return result;
}

#[no_mangle]
pub extern "C" fn get_key_pair(key_size: usize) -> RsaKeyPair {
    let mut rng: OsRng = OsRng;
    let private_key: RsaPrivateKey =
        RsaPrivateKey::new(&mut rng, key_size).expect("failed to generate a key");
    let public_key: RsaPublicKey = private_key.to_public_key();
    let key_pair = RsaKeyPair {
        pub_key: CString::new(
            public_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .unwrap()
                .to_string(),
        )
        .unwrap()
        .into_raw(),
        priv_key: CString::new(
            private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string(),
        )
        .unwrap()
        .into_raw(),
    };
    return key_pair;
}

#[no_mangle]
pub extern "C" fn get_key_pair_threadpool(rsa_key_size: usize) -> RsaKeyPair {
    let (sender, receiver) = mpsc::channel();
    rayon::spawn(move || {
        let mut rng: OsRng = OsRng;
        let private_key: RsaPrivateKey = RsaPrivateKey::new(&mut rng, rsa_key_size).expect("failed to generate a key");
        let public_key: RsaPublicKey = private_key.to_public_key();
        let thread_result = RsaKeyGenerationThreadPool {
            private_key: private_key,
            public_key: public_key
        };
        sender.send(thread_result);
    });
    let thread_result: RsaKeyGenerationThreadPool = receiver.recv().unwrap();
    let result = RsaKeyPair {
        priv_key: CString::new(
            thread_result.private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string(),
        )
        .unwrap()
        .into_raw(),
        pub_key: CString::new(
            thread_result.public_key
                .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
                .unwrap()
                .to_string(),
        )
        .unwrap()
        .into_raw()
    };
    result
}

#[no_mangle]
pub extern "C" fn rsa_sign_with_key_bytes(
    private_key: *const c_char,
    data_to_sign: *const c_uchar,
    data_to_sign_length: usize,
) -> RsaSignBytesResults {
    let private_key_string = unsafe {
        assert!(!private_key.is_null());

        CStr::from_ptr(private_key)
    }
    .to_str()
    .unwrap();
    let data_to_sign_slice: &[u8] = unsafe {
        assert!(!data_to_sign.is_null());
        std::slice::from_raw_parts(data_to_sign, data_to_sign_length)
    };
    let private_key =
        RsaPrivateKey::from_pkcs8_pem(private_key_string).expect("failed to generate a key");
    let mut signed_data = private_key
        .sign(PaddingScheme::new_pkcs1v15_sign_raw(), data_to_sign_slice)
        .unwrap();
    let capacity = signed_data.capacity();
    signed_data.reserve_exact(capacity);
    let result = RsaSignBytesResults {
        signature_raw_ptr: signed_data.as_mut_ptr(),
        length: signed_data.len(),
    };
    std::mem::forget(signed_data);
    return result;
}

#[test]
fn rsa_sign_nonffi_test() {
    let mut rng: OsRng = OsRng;
    let private_key: RsaPrivateKey =
        RsaPrivateKey::new(&mut rng, 2094).expect("failed to generate a key");
    let public_key: RsaPublicKey = private_key.to_public_key();
    let data = b"testing";
    let signature = private_key
        .sign(PaddingScheme::new_pkcs1v15_sign_raw(), data)
        .unwrap();
    assert_ne!(data.as_slice(), signature);
}

#[no_mangle]
pub extern "C" fn rsa_verify_bytes(
    public_key: *const c_char,
    data_to_verify: *const c_uchar,
    data_to_verify_length: usize,
    signature: *const c_uchar,
    signature_length: usize,
) -> bool {
    let public_key_string = unsafe {
        assert!(!public_key.is_null());

        CStr::from_ptr(public_key)
    }
    .to_str()
    .unwrap();
    let data_to_verify_slice: &[u8] = unsafe {
        assert!(!data_to_verify.is_null());
        std::slice::from_raw_parts(data_to_verify, data_to_verify_length)
    };
    let signature_slice: &[u8] = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    };
    let public_key = RsaPublicKey::from_pkcs1_pem(public_key_string).unwrap();
    let verified = public_key.verify(
        PaddingScheme::new_pkcs1v15_sign_raw(),
        &data_to_verify_slice,
        &signature_slice,
    );
    if verified.is_err() == false {
        return true;
    } else {
        return false;
    }
}

#[test]
fn rsa_verify_nonffi_test() {
    let mut rng: OsRng = OsRng;
    let private_key: RsaPrivateKey =
        RsaPrivateKey::new(&mut rng, 2094).expect("failed to generate a key");
    let public_key: RsaPublicKey = private_key.to_public_key();
    let data = "testing".as_bytes();
    let signature = private_key
        .sign(PaddingScheme::new_pkcs1v15_sign_raw(), data)
        .unwrap();
    let verified = public_key.verify(PaddingScheme::new_pkcs1v15_sign_raw(), &data, &signature);
    assert_eq!(verified.is_err(), false);
}

#[test]
fn get_key_pair_test() {
    let key_size = 4096 as usize;
    let key_pair = get_key_pair(key_size);
    assert!(!key_pair.pub_key.is_null());
    assert!(!key_pair.priv_key.is_null());
}
