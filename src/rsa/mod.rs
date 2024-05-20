use std::ffi::{c_char, c_uchar, CStr, CString};

use cas_lib::asymmetric::cas_asymmetric_encryption::CASRSAEncryption;
use cas_lib::asymmetric::cas_rsa::CASRSA;
use cas_lib::asymmetric::types::RSAKeyPairResult;
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};

mod types;
use self::types::{RsaDecryptBytesResult, RsaEncryptBytesResult, RsaKeyPair, RsaSignBytesResults};

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
    .unwrap()
    .to_string();

    let data_to_encrypt_slice = unsafe {
        assert!(!data_to_encrypt.is_null());
        std::slice::from_raw_parts(data_to_encrypt, data_to_encrypt_length)
    }.to_vec();
    let mut encrypted_bytes = <CASRSA as CASRSAEncryption>::encrypt_plaintext(pub_key_string, data_to_encrypt_slice);
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
    .unwrap()
    .to_string();

    let data_to_encrypt_slice = unsafe {
        assert!(!data_to_encrypt.is_null());
        std::slice::from_raw_parts(data_to_encrypt, data_to_encrypt_length)
    }
    .to_vec();

    let mut encrypted_bytes = <CASRSA as CASRSAEncryption>::encrypt_plaintext_threadpool(pub_key_string, data_to_encrypt_slice);
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
    .unwrap()
    .to_string();

    let data_to_decrypt_slice = unsafe {
        assert!(!data_to_decrypt.is_null());
        std::slice::from_raw_parts(data_to_decrypt, data_to_decrypt_length)
    }.to_vec();

    let mut decrypted_bytes = <CASRSA as CASRSAEncryption>::decrypt_ciphertext(priv_key_string, data_to_decrypt_slice);
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
    .unwrap()
    .to_string();

    let data_to_decrypt_slice = unsafe {
        assert!(!data_to_decrypt.is_null());
        std::slice::from_raw_parts(data_to_decrypt, data_to_decrypt_length)
    }.to_vec();
    let mut decrypted_bytes = <CASRSA as CASRSAEncryption>::decrypt_ciphertext_threadpool(priv_key_string, data_to_decrypt_slice);
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
    let key_pair = <CASRSA as CASRSAEncryption>::generate_rsa_keys(key_size);
    let result = RsaKeyPair {
        priv_key: CString::new(key_pair.private_key).unwrap().into_raw(),
        pub_key: CString::new(key_pair.public_key).unwrap().into_raw()
    };
    result
}

#[no_mangle]
pub extern "C" fn get_key_pair_threadpool(rsa_key_size: usize) -> RsaKeyPair {
    let rsa_key_result: RSAKeyPairResult = <CASRSA as CASRSAEncryption>::generate_rsa_keys_threadpool(rsa_key_size);
    let result = RsaKeyPair {
        priv_key: CString::new(rsa_key_result.private_key).unwrap().into_raw(),
        pub_key: CString::new(rsa_key_result.public_key).unwrap().into_raw()
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
    .unwrap()
    .to_string();

    let data_to_sign_slice = unsafe {
        assert!(!data_to_sign.is_null());
        std::slice::from_raw_parts(data_to_sign, data_to_sign_length)
    }.to_vec();
    let mut signed_data = <CASRSA as CASRSAEncryption>::sign(private_key_string, data_to_sign_slice);
    let capacity = signed_data.capacity();
    signed_data.reserve_exact(capacity);
    let result = RsaSignBytesResults {
        signature_raw_ptr: signed_data.as_mut_ptr(),
        length: signed_data.len(),
    };
    std::mem::forget(signed_data);
    return result;
}

#[no_mangle]
pub extern "C" fn rsa_sign_with_key_bytes_threadpool(
    private_key: *const c_char,
    data_to_sign: *const c_uchar,
    data_to_sign_length: usize,
) -> RsaSignBytesResults {
    let private_key_string = unsafe {
        assert!(!private_key.is_null());

        CStr::from_ptr(private_key)
    }
    .to_str()
    .unwrap()
    .to_string();

    let data_to_sign_slice = unsafe {
        assert!(!data_to_sign.is_null());
        std::slice::from_raw_parts(data_to_sign, data_to_sign_length)
    }.to_vec();

    let mut signed_data = <CASRSA as CASRSAEncryption>::sign_threadpool(private_key_string, data_to_sign_slice);
    let capacity = signed_data.capacity();
    signed_data.reserve_exact(capacity);
    let result = RsaSignBytesResults {
        signature_raw_ptr: signed_data.as_mut_ptr(),
        length: signed_data.len(),
    };
    std::mem::forget(signed_data);
    return result;
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
    .unwrap()
    .to_string();

    let data_to_verify_slice = unsafe {
        assert!(!data_to_verify.is_null());
        std::slice::from_raw_parts(data_to_verify, data_to_verify_length)
    }.to_vec();

    let signature_slice = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }.to_vec();
    let verified = <CASRSA as CASRSAEncryption>::verify(public_key_string, data_to_verify_slice, signature_slice);
    verified
}

#[no_mangle]
pub extern "C" fn rsa_verify_bytes_threadpool(
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
    .unwrap()
    .to_string();

    let data_to_verify_slice = unsafe {
        assert!(!data_to_verify.is_null());
        std::slice::from_raw_parts(data_to_verify, data_to_verify_length)
    }.to_vec();

    let signature_slice = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }.to_vec();
    let verified = <CASRSA as CASRSAEncryption>::verify_threadpool(public_key_string, data_to_verify_slice, signature_slice);
    verified
}

#[test]
fn get_key_pair_test() {
    let key_size = 4096 as usize;
    let key_pair = get_key_pair(key_size);
    assert!(!key_pair.pub_key.is_null());
    assert!(!key_pair.priv_key.is_null());
}
