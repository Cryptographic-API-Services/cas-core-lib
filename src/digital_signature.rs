
use std::ffi::{c_char, c_uchar, CString};

use rsa::{RsaPrivateKey, RsaPublicKey, PaddingScheme, rand_core::OsRng, pkcs1::EncodeRsaPublicKey, pkcs8::EncodePrivateKey};
use sha3::{Digest, Sha3_256, Sha3_512};

#[repr(C)]
pub struct SHARSADigitalSignatureResult {
    pub private_key: *mut c_char,
    pub public_key: *mut c_char,
    pub signature_raw_ptr: *mut c_uchar,
    pub length: usize
}

#[no_mangle]
pub extern "C" fn sha_512_rsa_digital_signature(rsa_key_size: usize, data_to_sign: *const c_uchar, data_length: usize) -> SHARSADigitalSignatureResult {
    assert!(!data_to_sign.is_null());
    let data_to_sign_slice = unsafe {std::slice::from_raw_parts(data_to_sign, data_length)};
    if rsa_key_size != 1024 && rsa_key_size != 2048 && rsa_key_size != 4096 {
        panic!("Not a valid RSA key length");
    }
    let mut hasher = Sha3_512::new();
    hasher.update(data_to_sign_slice);
    let sha_hasher_result = hasher.finalize();
    let mut rng: OsRng = OsRng;
    let private_key: RsaPrivateKey = RsaPrivateKey::new(&mut rng, rsa_key_size).expect("failed to generate a key");
    let public_key: RsaPublicKey = private_key.to_public_key();
    let mut signed_data = private_key.sign(PaddingScheme::new_pkcs1v15_sign_raw(), &sha_hasher_result).unwrap();
    let capacity = signed_data.capacity();
    signed_data.reserve_exact(capacity);
    let result = SHARSADigitalSignatureResult {
        public_key: CString::new(public_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string()).unwrap().into_raw(),
        private_key: CString::new(private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap().to_string()).unwrap().into_raw(),
        signature_raw_ptr: signed_data.as_mut_ptr(),
        length: signed_data.len(),
    };
    std::mem::forget(signed_data);
    result
}