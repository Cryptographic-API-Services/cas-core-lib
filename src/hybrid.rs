use std::ffi::{c_char, c_uchar, CStr, CString};

use aes_gcm::{
    aead::{generic_array::GenericArray, AeadMut, OsRng},
    Aes128Gcm, Aes256Gcm, Key, KeyInit, Nonce, Key
};
use rsa::{RsaPrivateKey, RsaPublicKey};

enum AesKey {
    Aes128(Key<Aes128Gcm>),
    Aes256(Key<Aes256Gcm>)
}
enum AesCipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm)
}

#[repr(C)]
pub struct AESRSAHybridInitializer {
    pub aesType: usize,
    pub rsaType: usize,
    pub aesNonce: *mut c_char,
}

#[no_mangle]
pub extern "C" fn hybrid_encryption(data_to_encrypt: *mut c_uchar, data_to_encrypt_length: usize, initalizer: AESRSAHybridInitializer) {
    let to_encrypt_slice: &[u8] = unsafe { std::slice::from_raw_parts(data_to_encrypt, data_to_encrypt_length) };
    let mut rng: OsRng = OsRng;
    let private_key: RsaPrivateKey = RsaPrivateKey::new(&mut rng, initalizer.rsaType).expect("failed to generate a key");
    let public_key: RsaPublicKey = private_key.to_public_key();
    let aes_key: AesKey;
    if (initalizer.aesType == 128) {
        aes_key = AesKey::Aes128(Aes128Gcm::generate_key(&mut OsRng));
    } else {
        aes_key = AesKey::Aes256(Aes256Gcm::generate_key(&mut OsRng));
    }
    let aes_nonce = unsafe {
        assert!(!initalizer.aesNonce.is_null());
        CStr::from_ptr(initalizer.aesNonce)
    }
    .to_str()
    .unwrap()
    .as_bytes();
    let aes_nonce = Nonce::from_slice(aes_nonce);
    let ciphertext: Vec<u8>;
    match aes_key {
        AesKey::Aes128(key) => {
            let mut cipher = Aes128Gcm::new(&key);
            ciphertext = cipher.encrypt(&aes_nonce, to_encrypt_slice).unwrap();
        }
        AesKey::Aes256(key) => {
            let mut cipher = Aes256Gcm::new(&key);
            ciphertext = cipher.encrypt(&aes_nonce, to_encrypt_slice).unwrap();
        }
    }
}