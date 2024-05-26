use std::ffi::{c_char, c_uchar, CStr, CString};

use cas_lib::digital_signature::{cas_digital_signature_rsa::RSADigitalSignature, sha_256_rsa::SHA256RSADigitalSignature, sha_512_rsa::SHA512RSADigitalSignature};
use ed25519_dalek::{Keypair, Signature, Signer, Verifier};
use sha3::{Digest, Sha3_256, Sha3_512};

#[repr(C)]
pub struct SHARSADigitalSignatureResult {
    pub private_key: *mut c_char,
    pub public_key: *mut c_char,
    pub signature_raw_ptr: *mut c_uchar,
    pub length: usize,
}

#[repr(C)]
pub struct SHAED25519DalekDigitalSignatureResult {
    pub public_key: *mut c_uchar,
    pub public_key_length: usize,
    pub signature_raw_ptr: *mut c_uchar,
    pub signature_length: usize,
}

#[no_mangle]
pub extern "C" fn sha_512_rsa_digital_signature(
    rsa_key_size: usize,
    data_to_sign: *const c_uchar,
    data_length: usize,
) -> SHARSADigitalSignatureResult {
    assert!(!data_to_sign.is_null());
    let data_to_sign_slice = unsafe { std::slice::from_raw_parts(data_to_sign, data_length) }.to_vec();
    if rsa_key_size != 1024 && rsa_key_size != 2048 && rsa_key_size != 4096 {
        panic!("Not a valid RSA key length");
    }
    let result = <SHA512RSADigitalSignature as RSADigitalSignature>::digital_signature_rsa(rsa_key_size as u32, data_to_sign_slice);
    let mut signed_data = result.signature;
    let capacity = signed_data.capacity();
    signed_data.reserve_exact(capacity);
    let result = SHARSADigitalSignatureResult {
        public_key: CString::new(result.public_key).unwrap().into_raw(),
        private_key: CString::new(result.private_key).unwrap().into_raw(),
        signature_raw_ptr: signed_data.as_mut_ptr(),
        length: signed_data.len(),
    };
    std::mem::forget(signed_data);
    result
}

#[no_mangle]
pub extern "C" fn sha_256_rsa_digital_signature(
    rsa_key_size: usize,
    data_to_sign: *const c_uchar,
    data_length: usize,
) -> SHARSADigitalSignatureResult {
    assert!(!data_to_sign.is_null());
    let data_to_sign_slice = unsafe { std::slice::from_raw_parts(data_to_sign, data_length) }.to_vec();
    if rsa_key_size != 1024 && rsa_key_size != 2048 && rsa_key_size != 4096 {
        panic!("Not a valid RSA key length");
    }
    let result = <SHA256RSADigitalSignature as RSADigitalSignature>::digital_signature_rsa(rsa_key_size as u32, data_to_sign_slice);
    let mut signed_data = result.signature;
    let capacity = signed_data.capacity();
    signed_data.reserve_exact(capacity);
    let result = SHARSADigitalSignatureResult {
        public_key: CString::new(result.public_key).unwrap().into_raw(),
        private_key: CString::new(result.private_key).unwrap().into_raw(),
        signature_raw_ptr: signed_data.as_mut_ptr(),
        length: signed_data.len(),
    };
    std::mem::forget(signed_data);
    result
}

#[no_mangle]
pub extern "C" fn sha_512_rsa_digital_signature_verify(
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
    let data_to_verify_slice: Vec<u8> = unsafe {
        assert!(!data_to_verify.is_null());
        std::slice::from_raw_parts(data_to_verify, data_to_verify_length)
    }.to_vec();
    let signature_slice: Vec<u8> = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }.to_vec();
    let result = <SHA512RSADigitalSignature as RSADigitalSignature>::verify_rsa(public_key_string, data_to_verify_slice, signature_slice);
    result
}

#[no_mangle]
pub extern "C" fn sha_256_rsa_digital_signature_verify(
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
    let data_to_verify_slice: Vec<u8> = unsafe {
        assert!(!data_to_verify.is_null());
        std::slice::from_raw_parts(data_to_verify, data_to_verify_length)
    }.to_vec();
    let signature_slice: Vec<u8> = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }.to_vec();
    let result = <SHA256RSADigitalSignature as RSADigitalSignature>::verify_rsa(public_key_string, data_to_verify_slice, signature_slice);
    result
}

#[no_mangle]
pub extern "C" fn sha512_ed25519_digital_signature(
    data_to_sign: *const c_uchar,
    data_length: usize,
) -> SHAED25519DalekDigitalSignatureResult {
    let data_to_sign_slice = unsafe {
        assert!(!data_to_sign.is_null());
        std::slice::from_raw_parts(data_to_sign, data_length)
    };

    let mut hasher = Sha3_512::new();
    hasher.update(data_to_sign_slice);
    let sha_hasher_result = hasher.finalize();

    let mut csprng = rand_07::rngs::OsRng {};
    let keypair = Keypair::generate(&mut csprng);

    let signature = keypair.sign(&sha_hasher_result);
    let signature_bytes = signature.to_bytes();
    let public_keypair_bytes = keypair.public.to_bytes();

    return unsafe {
        let size_of_public_key = std::mem::size_of_val(&public_keypair_bytes);
        let public_key_raw_ptr = libc::malloc(size_of_public_key) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(
            public_keypair_bytes.as_ptr(),
            public_key_raw_ptr,
            size_of_public_key,
        );

        let size_of_signature = std::mem::size_of_val(&signature_bytes);
        let signature_raw_ptr = libc::malloc(size_of_signature) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(
            signature_bytes.as_ptr(),
            signature_raw_ptr,
            size_of_signature,
        );

        let result = SHAED25519DalekDigitalSignatureResult {
            public_key: public_key_raw_ptr,
            public_key_length: size_of_public_key,
            signature_raw_ptr: signature_raw_ptr,
            signature_length: size_of_signature,
        };
        result
    };
}

#[no_mangle]
pub extern "C" fn sha256_ed25519_digital_signature(
    data_to_sign: *const c_uchar,
    data_length: usize,
) -> SHAED25519DalekDigitalSignatureResult {
    let data_to_sign_slice = unsafe {
        assert!(!data_to_sign.is_null());
        std::slice::from_raw_parts(data_to_sign, data_length)
    };

    let mut hasher = Sha3_256::new();
    hasher.update(data_to_sign_slice);
    let sha_hasher_result = hasher.finalize();

    let mut csprng = rand_07::rngs::OsRng {};
    let keypair = Keypair::generate(&mut csprng);

    let signature = keypair.sign(&sha_hasher_result);
    let signature_bytes = signature.to_bytes();
    let public_keypair_bytes = keypair.public.to_bytes();

    return unsafe {
        let size_of_public_key = std::mem::size_of_val(&public_keypair_bytes);
        let public_key_raw_ptr = libc::malloc(size_of_public_key) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(
            public_keypair_bytes.as_ptr(),
            public_key_raw_ptr,
            size_of_public_key,
        );

        let size_of_signature = std::mem::size_of_val(&signature_bytes);
        let signature_raw_ptr = libc::malloc(size_of_signature) as *mut c_uchar;
        std::ptr::copy_nonoverlapping(
            signature_bytes.as_ptr(),
            signature_raw_ptr,
            size_of_signature,
        );

        let result = SHAED25519DalekDigitalSignatureResult {
            public_key: public_key_raw_ptr,
            public_key_length: size_of_public_key,
            signature_raw_ptr: signature_raw_ptr,
            signature_length: size_of_signature,
        };
        result
    };
}

#[no_mangle]
pub extern "C" fn sha512_ed25519_digital_signature_verify(
    public_key: *const c_uchar,
    public_key_length: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_length: usize,
    signature: *const c_uchar,
    signature_length: usize,
) -> bool {
    let public_key_slice = unsafe {
        assert!(!public_key.is_null());
        std::slice::from_raw_parts(public_key, public_key_length)
    };
    let data_to_verify_slice = unsafe {
        assert!(!data_to_verify.is_null());
        std::slice::from_raw_parts(data_to_verify, data_to_verify_length)
    };
    let signature_slice = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    };

    let mut hasher = Sha3_512::new();
    hasher.update(data_to_verify_slice);
    let sha_hasher_result = hasher.finalize();

    let public_key_parsed = ed25519_dalek::PublicKey::from_bytes(&public_key_slice).unwrap();
    let signature_parsed = Signature::from_bytes(&signature_slice).unwrap();
    return public_key_parsed
        .verify(&sha_hasher_result, &signature_parsed)
        .is_ok();
}

#[no_mangle]
pub extern "C" fn sha256_ed25519_digital_signature_verify(
    public_key: *const c_uchar,
    public_key_length: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_length: usize,
    signature: *const c_uchar,
    signature_length: usize,
) -> bool {
    let public_key_slice = unsafe {
        assert!(!public_key.is_null());
        std::slice::from_raw_parts(public_key, public_key_length)
    };
    let data_to_verify_slice = unsafe {
        assert!(!data_to_verify.is_null());
        std::slice::from_raw_parts(data_to_verify, data_to_verify_length)
    };
    let signature_slice = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    };

    let mut hasher = Sha3_256::new();
    hasher.update(data_to_verify_slice);
    let sha_hasher_result = hasher.finalize();

    let public_key_parsed = ed25519_dalek::PublicKey::from_bytes(&public_key_slice).unwrap();
    let signature_parsed = Signature::from_bytes(&signature_slice).unwrap();
    return public_key_parsed
        .verify(&sha_hasher_result, &signature_parsed)
        .is_ok();
}
