
use sha3::{Digest, Sha3_256, Sha3_512};

mod sha;

#[no_mangle]
pub extern "C" fn sha_512_rsa_digital_signature(rsa_key_size: usize, data_to_sign: *const c_uchar, data_length: usize) {
    assert!(!data_to_sign.is_null());
    let data_to_sign_slice = unsafe {std::slice::from_raw_parts(data_to_sign, data_length)};
    let mut hasher = Sha3_512::new();
    hasher.update(data_to_hash_slice);
    let sha_hasher_result = hasher.finalize();
    let mut rng: OsRng = OsRng;
    let private_key: RsaPrivateKey = RsaPrivateKey::new(&mut rng, rsa_key_size).expect("failed to generate a key");
    let public_key: RsaPublicKey = private_key.to_public_key();
    // TODO sign with private key
    // Create return struct for signature private and public key.
}