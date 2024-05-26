use std::ffi::{c_char, c_uchar, CStr, CString};

use cas_lib::digital_signature::{
    cas_digital_signature_rsa::{ED25519DigitalSignature, RSADigitalSignature},
    sha_256_ed25519::SHA256ED25519DigitalSignature,
    sha_256_rsa::SHA256RSADigitalSignature,
    sha_512_ed25519::SHA512ED25519DigitalSignature,
    sha_512_rsa::SHA512RSADigitalSignature,
};

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
    let data_to_sign_slice =
        unsafe { std::slice::from_raw_parts(data_to_sign, data_length) }.to_vec();
    if rsa_key_size != 1024 && rsa_key_size != 2048 && rsa_key_size != 4096 {
        panic!("Not a valid RSA key length");
    }
    let result = <SHA512RSADigitalSignature as RSADigitalSignature>::digital_signature_rsa(
        rsa_key_size as u32,
        data_to_sign_slice,
    );
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
pub extern "C" fn sha_512_rsa_digital_signature_threadpool(
    rsa_key_size: usize,
    data_to_sign: *const c_uchar,
    data_length: usize,
) -> SHARSADigitalSignatureResult {
    assert!(!data_to_sign.is_null());
    let data_to_sign_slice =
        unsafe { std::slice::from_raw_parts(data_to_sign, data_length) }.to_vec();
    if rsa_key_size != 1024 && rsa_key_size != 2048 && rsa_key_size != 4096 {
        panic!("Not a valid RSA key length");
    }
    let result = <SHA512RSADigitalSignature as RSADigitalSignature>::digital_signature_rsa_threadpool(
        rsa_key_size as u32,
        data_to_sign_slice,
    );
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
    let data_to_sign_slice =
        unsafe { std::slice::from_raw_parts(data_to_sign, data_length) }.to_vec();
    if rsa_key_size != 1024 && rsa_key_size != 2048 && rsa_key_size != 4096 {
        panic!("Not a valid RSA key length");
    }
    let result = <SHA256RSADigitalSignature as RSADigitalSignature>::digital_signature_rsa(
        rsa_key_size as u32,
        data_to_sign_slice,
    );
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
pub extern "C" fn sha_256_rsa_digital_signature_threadpool(
    rsa_key_size: usize,
    data_to_sign: *const c_uchar,
    data_length: usize,
) -> SHARSADigitalSignatureResult {
    assert!(!data_to_sign.is_null());
    let data_to_sign_slice =
        unsafe { std::slice::from_raw_parts(data_to_sign, data_length) }.to_vec();
    if rsa_key_size != 1024 && rsa_key_size != 2048 && rsa_key_size != 4096 {
        panic!("Not a valid RSA key length");
    }
    let result = <SHA256RSADigitalSignature as RSADigitalSignature>::digital_signature_rsa_threadpool(
        rsa_key_size as u32,
        data_to_sign_slice,
    );
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
    }
    .to_vec();
    let signature_slice: Vec<u8> = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }
    .to_vec();
    let result = <SHA512RSADigitalSignature as RSADigitalSignature>::verify_rsa(
        public_key_string,
        data_to_verify_slice,
        signature_slice,
    );
    result
}

#[no_mangle]
pub extern "C" fn sha_512_rsa_digital_signature_verify_threadpool(
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
    }
    .to_vec();
    let signature_slice: Vec<u8> = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }
    .to_vec();
    let result = <SHA512RSADigitalSignature as RSADigitalSignature>::verify_rsa_threadpool(
        public_key_string,
        data_to_verify_slice,
        signature_slice,
    );
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
    }
    .to_vec();
    let signature_slice: Vec<u8> = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }
    .to_vec();
    let result = <SHA256RSADigitalSignature as RSADigitalSignature>::verify_rsa(
        public_key_string,
        data_to_verify_slice,
        signature_slice,
    );
    result
}

#[no_mangle]
pub extern "C" fn sha_256_rsa_digital_signature_verify_threadpool(
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
    }
    .to_vec();
    let signature_slice: Vec<u8> = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }
    .to_vec();
    let result = <SHA256RSADigitalSignature as RSADigitalSignature>::verify_rsa_threadpool(
        public_key_string,
        data_to_verify_slice,
        signature_slice,
    );
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
    }
    .to_vec();
    let result =
        <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519(
            data_to_sign_slice,
        );
    let mut public_key = result.public_key;
    let public_key_capacity = public_key.capacity();
    public_key.reserve_exact(public_key_capacity);
    let mut signature = result.signature;
    let signature_capacity = signature.capacity();
    signature.reserve_exact(signature_capacity);
    let result = SHAED25519DalekDigitalSignatureResult {
        public_key: public_key.as_mut_ptr(),
        public_key_length: public_key.len(),
        signature_raw_ptr: signature.as_mut_ptr(),
        signature_length: signature.len(),
    };
    std::mem::forget(public_key);
    std::mem::forget(signature);
    result
}

#[no_mangle]
pub extern "C" fn sha512_ed25519_digital_signature_threadpool(
    data_to_sign: *const c_uchar,
    data_length: usize,
) -> SHAED25519DalekDigitalSignatureResult {
    let data_to_sign_slice = unsafe {
        assert!(!data_to_sign.is_null());
        std::slice::from_raw_parts(data_to_sign, data_length)
    }
    .to_vec();
    let result =
        <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519_threadpool(
            data_to_sign_slice,
        );
    let mut public_key = result.public_key;
    let public_key_capacity = public_key.capacity();
    public_key.reserve_exact(public_key_capacity);
    let mut signature = result.signature;
    let signature_capacity = signature.capacity();
    signature.reserve_exact(signature_capacity);
    let result = SHAED25519DalekDigitalSignatureResult {
        public_key: public_key.as_mut_ptr(),
        public_key_length: public_key.len(),
        signature_raw_ptr: signature.as_mut_ptr(),
        signature_length: signature.len(),
    };
    std::mem::forget(public_key);
    std::mem::forget(signature);
    result
}

#[no_mangle]
pub extern "C" fn sha256_ed25519_digital_signature(
    data_to_sign: *const c_uchar,
    data_length: usize,
) -> SHAED25519DalekDigitalSignatureResult {
    let data_to_sign_slice = unsafe {
        assert!(!data_to_sign.is_null());
        std::slice::from_raw_parts(data_to_sign, data_length)
    }
    .to_vec();
    let result =
        <SHA256ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519(
            data_to_sign_slice,
        );
    let mut public_key = result.public_key;
    let public_key_capacity = public_key.capacity();
    public_key.reserve_exact(public_key_capacity);
    let mut signature = result.signature;
    let signature_capacity = signature.capacity();
    signature.reserve_exact(signature_capacity);
    let result = SHAED25519DalekDigitalSignatureResult {
        public_key: public_key.as_mut_ptr(),
        public_key_length: public_key.len(),
        signature_raw_ptr: signature.as_mut_ptr(),
        signature_length: signature.len(),
    };
    std::mem::forget(public_key);
    std::mem::forget(signature);
    result
}

#[no_mangle]
pub extern "C" fn sha256_ed25519_digital_signature_threadpool(
    data_to_sign: *const c_uchar,
    data_length: usize,
) -> SHAED25519DalekDigitalSignatureResult {
    let data_to_sign_slice = unsafe {
        assert!(!data_to_sign.is_null());
        std::slice::from_raw_parts(data_to_sign, data_length)
    }
    .to_vec();
    let result =
        <SHA256ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519_threadpool(
            data_to_sign_slice,
        );
    let mut public_key = result.public_key;
    let public_key_capacity = public_key.capacity();
    public_key.reserve_exact(public_key_capacity);
    let mut signature = result.signature;
    let signature_capacity = signature.capacity();
    signature.reserve_exact(signature_capacity);
    let result = SHAED25519DalekDigitalSignatureResult {
        public_key: public_key.as_mut_ptr(),
        public_key_length: public_key.len(),
        signature_raw_ptr: signature.as_mut_ptr(),
        signature_length: signature.len(),
    };
    std::mem::forget(public_key);
    std::mem::forget(signature);
    result
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
    }
    .to_vec();
    let data_to_verify_slice = unsafe {
        assert!(!data_to_verify.is_null());
        std::slice::from_raw_parts(data_to_verify, data_to_verify_length)
    }
    .to_vec();
    let signature_slice = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }
    .to_vec();
    let result = <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519_verify(public_key_slice, data_to_verify_slice,  signature_slice);
    result
}

#[no_mangle]
pub extern "C" fn sha512_ed25519_digital_signature_verify_threadpool(
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
    }
    .to_vec();
    let data_to_verify_slice = unsafe {
        assert!(!data_to_verify.is_null());
        std::slice::from_raw_parts(data_to_verify, data_to_verify_length)
    }
    .to_vec();
    let signature_slice = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }
    .to_vec();
    let result = <SHA512ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519_verify_threadpool(public_key_slice, data_to_verify_slice,  signature_slice);
    result
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
    }
    .to_vec();
    let data_to_verify_slice = unsafe {
        assert!(!data_to_verify.is_null());
        std::slice::from_raw_parts(data_to_verify, data_to_verify_length)
    }
    .to_vec();
    let signature_slice = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }
    .to_vec();
    let result = <SHA256ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519_verify(public_key_slice, data_to_verify_slice,  signature_slice);
    result
}

#[no_mangle]
pub extern "C" fn sha256_ed25519_digital_signature_verify_threadpool(
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
    }
    .to_vec();
    let data_to_verify_slice = unsafe {
        assert!(!data_to_verify.is_null());
        std::slice::from_raw_parts(data_to_verify, data_to_verify_length)
    }
    .to_vec();
    let signature_slice = unsafe {
        assert!(!signature.is_null());
        std::slice::from_raw_parts(signature, signature_length)
    }
    .to_vec();
    let result = <SHA256ED25519DigitalSignature as ED25519DigitalSignature>::digital_signature_ed25519_verify_threadpool(public_key_slice, data_to_verify_slice,  signature_slice);
    result
}