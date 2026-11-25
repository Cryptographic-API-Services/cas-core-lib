use std::ffi::{c_char, c_uchar, CStr, CString};
use cas_lib::error::{CasError, CasResult};
use cas_lib::password_hashers::argon2::CASArgon;

use super::types::{Argon2DerivedKey, Argon2KDFAes128, Argon2Salt};
use crate::helpers::{cas_error_code, export_bytes, string_from_c_str, string_result, utf8_from_ffi, verify_result, CasStringResult, CasVerifyResult};

// Passwords cross the ABI as a pointer + length (`*_bytes` functions), so they
// may contain NUL bytes. cas-lib's hash and verify functions take `String`:
// bytes that are not valid UTF-8 return `InvalidInput` (4). None of these
// functions panic: a null pointer with a non-zero length returns `InvalidInput`.

/// Rebuilds an input buffer from a pointer + length pair. A null pointer is
/// accepted for a zero-length buffer and is `InvalidInput` otherwise.
fn input_bytes(ptr: *const c_uchar, len: usize) -> CasResult<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(CasError::InvalidInput);
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec())
}

/// Hashes a password with Argon2id. `memory_cost` is in **MiB** (19–4096),
/// `iterations` 1–10 and `parallelism` 1–16. Out-of-range values return
/// `InvalidParameters` (6) instead of allocating. The password is
/// `password_length` bytes of UTF-8 and may contain NUL bytes.
#[no_mangle]
pub extern "C" fn argon2_hash_password_parameters_bytes(
    memory_cost: u32,
    iterations: u32,
    parallelism: u32,
    password: *const c_uchar,
    password_length: usize,
) -> CasStringResult {
    string_result(utf8_from_ffi(password, password_length).and_then(|password| {
        CASArgon::hash_password_parameters(memory_cost, iterations, parallelism, password)
    }))
}

/// Hashes a password with Argon2id's default parameters. The password is
/// `password_length` bytes of UTF-8 and may contain NUL bytes.
#[no_mangle]
pub extern "C" fn argon2_hash_bytes(password: *const c_uchar, password_length: usize) -> CasStringResult {
    string_result(utf8_from_ffi(password, password_length).and_then(CASArgon::hash_password))
}

/// Verifies a password against an Argon2 hash (a NUL-terminated string). The
/// password is `password_length` bytes of UTF-8.
#[no_mangle]
pub extern "C" fn argon2_verify_bytes(
    hashed_password: *const c_char,
    password: *const c_uchar,
    password_length: usize,
) -> CasVerifyResult {
    verify_result(
        string_from_c_str(hashed_password)
            .and_then(|hash| Ok((hash, utf8_from_ffi(password, password_length)?)))
            .and_then(|(hash, password)| CASArgon::verify_password(hash, password)),
    )
}

/// Deprecated: the password is a C string, so it ends at the first NUL byte.
/// Use `argon2_hash_password_parameters_bytes`. A null pointer or invalid UTF-8
/// returns `InvalidInput` (4); out-of-range parameters return `InvalidParameters` (6).
#[deprecated(note = "the password is cut at the first NUL byte; use argon2_hash_password_parameters_bytes")]
#[no_mangle]
pub extern "C" fn argon2_hash_password_parameters(memory_cost: u32, iterations: u32, parallelism: u32, password_to_hash: *const c_char) -> CasStringResult {
    string_result(string_from_c_str(password_to_hash).and_then(|password| {
        CASArgon::hash_password_parameters(memory_cost, iterations, parallelism, password)
    }))
}

#[test]
#[allow(deprecated)]
fn argon2_hash_password_parameters_test() {
    let password = "TestPassword123!";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();

    let hash = argon2_hash_password_parameters(19, 2, 1, password_bytes.as_ptr() as *const i8);
    let hash_cstr = unsafe { CString::from_raw(hash.value) };
    let hash_str = hash_cstr.to_str().unwrap();
    assert!(!hash_str.is_empty());
    assert_ne!(hash_str, password);
}

/// Returns a random 16-byte salt for `argon2_derive_aes_128_key_with_salt` and
/// `argon2_derive_aes_256_key_with_salt`. The salt is not secret: store it next to
/// whatever the key protects and pass it back to re-derive the same key.
#[no_mangle]
pub extern "C" fn argon2_generate_salt() -> Argon2Salt {
    let salt = CASArgon::generate_salt();
    Argon2Salt {
        salt: export_bytes(&salt),
        length: salt.len(),
    }
}

fn derive_key_with_salt(
    derive: fn(Vec<u8>, Vec<u8>) -> CasResult<Vec<u8>>,
    password: *const c_uchar,
    password_length: usize,
    salt: *const c_uchar,
    salt_length: usize,
) -> Argon2DerivedKey {
    let result = input_bytes(password, password_length)
        .and_then(|password| Ok((password, input_bytes(salt, salt_length)?)))
        .and_then(|(password, salt)| derive(password, salt));
    match result {
        Ok(key) => Argon2DerivedKey {
            key: export_bytes(&key),
            length: key.len(),
            error_code: 0,
        },
        Err(e) => Argon2DerivedKey {
            key: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

/// Derives a 16-byte AES-128 key from a password and salt with Argon2id (19 MiB,
/// 2 iterations, parallelism 1). The same password and salt always give the same
/// key. A salt shorter than 16 bytes returns `InvalidParameters` (6); a null
/// pointer with a non-zero length returns `InvalidInput` (4).
#[no_mangle]
pub extern "C" fn argon2_derive_aes_128_key_with_salt(
    password: *const c_uchar,
    password_length: usize,
    salt: *const c_uchar,
    salt_length: usize,
) -> Argon2DerivedKey {
    derive_key_with_salt(CASArgon::derive_aes_128_key_with_salt, password, password_length, salt, salt_length)
}

/// Derives a 32-byte AES-256 key from a password and salt with Argon2id (19 MiB,
/// 2 iterations, parallelism 1). The same password and salt always give the same
/// key. A salt shorter than 16 bytes returns `InvalidParameters` (6); a null
/// pointer with a non-zero length returns `InvalidInput` (4).
#[no_mangle]
pub extern "C" fn argon2_derive_aes_256_key_with_salt(
    password: *const c_uchar,
    password_length: usize,
    salt: *const c_uchar,
    salt_length: usize,
) -> Argon2DerivedKey {
    derive_key_with_salt(CASArgon::derive_aes_256_key_with_salt, password, password_length, salt, salt_length)
}

/// Deprecated: derives an AES-128 key with a random salt that is thrown away, so
/// the same password never gives the same key again. Use `argon2_generate_salt`
/// and `argon2_derive_aes_128_key_with_salt`.
#[deprecated(note = "the salt is discarded, so the key can't be re-derived; use argon2_generate_salt and argon2_derive_aes_128_key_with_salt")]
#[allow(deprecated)]
#[no_mangle]
pub extern "C" fn argon2_derive_aes_128_key(hashed_password: *const c_char) -> Argon2KDFAes128 {
    if hashed_password.is_null() {
        return Argon2KDFAes128 { key: std::ptr::null_mut(), length: 0, error_code: cas_error_code(&CasError::InvalidInput) };
    }
    let hashed_password_bytes = unsafe { CStr::from_ptr(hashed_password) }.to_bytes().to_vec();
    match CASArgon::derive_aes_128_key(hashed_password_bytes) {
        Ok(key) => {
            let key_ptr = export_bytes(&key);
            Argon2KDFAes128 {
                key: key_ptr,
                length: key.len(),
                error_code: 0,
            }
        }
        Err(e) => Argon2KDFAes128 {
            key: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

/// Deprecated: derives an AES-256 key with a random salt that is thrown away, so
/// the same password never gives the same key again. Use `argon2_generate_salt`
/// and `argon2_derive_aes_256_key_with_salt`.
#[deprecated(note = "the salt is discarded, so the key can't be re-derived; use argon2_generate_salt and argon2_derive_aes_256_key_with_salt")]
#[allow(deprecated)]
#[no_mangle]
pub extern "C" fn argon2_derive_aes_256_key(hashed_password: *const c_char) -> Argon2KDFAes128 {
    if hashed_password.is_null() {
        return Argon2KDFAes128 { key: std::ptr::null_mut(), length: 0, error_code: cas_error_code(&CasError::InvalidInput) };
    }
    let hashed_password_bytes = unsafe { CStr::from_ptr(hashed_password) }.to_bytes().to_vec();
    match CASArgon::derive_aes_256_key(hashed_password_bytes) {
        Ok(key) => {
            let key_ptr = export_bytes(&key);
            Argon2KDFAes128 {
                key: key_ptr,
                length: key.len(),
                error_code: 0,
            }
        }
        Err(e) => Argon2KDFAes128 {
            key: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

/// Deprecated: the password is a C string, so it ends at the first NUL byte.
/// Use `argon2_verify_bytes`. A null pointer or invalid UTF-8 returns `InvalidInput` (4).
#[deprecated(note = "the password is cut at the first NUL byte; use argon2_verify_bytes")]
#[no_mangle]
pub extern "C" fn argon2_verify(hashed_pass: *const c_char, password: *const c_char) -> CasVerifyResult {
    verify_result(
        string_from_c_str(hashed_pass)
            .and_then(|hash| Ok((hash, string_from_c_str(password)?)))
            .and_then(|(hash, password)| CASArgon::verify_password(hash, password)),
    )
}

#[test]
#[allow(deprecated)]
fn argon2_verify_test() {
    let password = "PasswordToVerify";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password = argon2_hash(password_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password.value) };
    let hashed_password_bytes = hashed_password_ctr.as_bytes_with_nul();
    let hashed_password_ptr = hashed_password_bytes.as_ptr() as *const i8;
    let is_valid = argon2_verify(hashed_password_ptr, password_ptr);
    assert_eq!(true, is_valid.is_valid);
}

/// Deprecated: the password is a C string, so it ends at the first NUL byte.
/// Use `argon2_hash_bytes`. A null pointer or invalid UTF-8 returns `InvalidInput` (4).
#[deprecated(note = "the password is cut at the first NUL byte; use argon2_hash_bytes")]
#[no_mangle]
pub extern "C" fn argon2_hash(pass_to_hash: *const c_char) -> CasStringResult {
    string_result(string_from_c_str(pass_to_hash).and_then(CASArgon::hash_password))
}

#[test]
#[allow(deprecated)]
fn argon2_hash_test() {
    let password = "DontUseThisPassword";
    let password_cstr = CString::new(password).unwrap();
    let password_bytes = password_cstr.as_bytes_with_nul();
    let password_ptr = password_bytes.as_ptr() as *const i8;
    let hashed_password_ptr = argon2_hash(password_ptr);
    let hashed_password_ctr = unsafe { CString::from_raw(hashed_password_ptr.value) };
    let hashed_password_str = hashed_password_ctr.to_str().unwrap();
    assert_ne!(password, hashed_password_str);
}

#[test]
#[allow(deprecated)]
fn argon2_hash_password_parameters_bounds_test() {
    let invalid_parameters = cas_error_code(&cas_lib::error::CasError::InvalidParameters);
    let password = CString::new("DoNotUseThisPassword").unwrap();
    // One past each bound, plus the value that used to wrap to 1 MiB in release builds (#92).
    for (memory_cost, iterations, parallelism) in [
        (18, 2, 1), (4097, 2, 1), (4_194_305, 2, 1),
        (19, 0, 1), (19, 11, 1),
        (19, 2, 0), (19, 2, 17),
    ] {
        let hash = argon2_hash_password_parameters(memory_cost, iterations, parallelism, password.as_ptr());
        assert!(hash.value.is_null());
        assert_eq!(invalid_parameters, hash.error_code);
    }
    // The lowest accepted memory cost is 19 MiB, stored as KiB in the PHC string.
    let hash = argon2_hash_password_parameters(19, 1, 1, password.as_ptr());
    assert_eq!(0, hash.error_code);
    let hash_string = unsafe { CString::from_raw(hash.value) }.into_string().unwrap();
    assert!(hash_string.contains("m=19456,t=1,p=1"));
}

#[test]
#[allow(deprecated)]
fn argon2_verify_refuses_hostile_stored_hash_test() {
    let invalid_parameters = cas_error_code(&cas_lib::error::CasError::InvalidParameters);
    let password = CString::new("DoNotUseThisPassword").unwrap();
    let hash = argon2_hash_password_parameters(19, 1, 1, password.as_ptr());
    let hash_string = unsafe { CString::from_raw(hash.value) }.into_string().unwrap();
    for hostile_params in ["m=4194305,t=1,p=1", "m=19456,t=11,p=1", "m=19456,t=1,p=17"] {
        let hostile = CString::new(hash_string.replace("m=19456,t=1,p=1", hostile_params)).unwrap();
        let is_valid = argon2_verify(hostile.as_ptr(), password.as_ptr());
        assert!(!is_valid.is_valid);
        assert_eq!(invalid_parameters, is_valid.error_code);
    }
}

#[test]
fn argon2_generate_salt_test() {
    let first = argon2_generate_salt();
    let second = argon2_generate_salt();
    assert_eq!(16, first.length);
    assert_eq!(16, second.length);
    let first_bytes = unsafe { std::slice::from_raw_parts(first.salt, first.length) }.to_vec();
    let second_bytes = unsafe { std::slice::from_raw_parts(second.salt, second.length) }.to_vec();
    assert_ne!(first_bytes, second_bytes);
    crate::helpers::free_bytes(first.salt);
    crate::helpers::free_bytes(second.salt);
}

#[cfg(test)]
fn derived_key_bytes(result: Argon2DerivedKey) -> Vec<u8> {
    assert_eq!(0, result.error_code);
    let key = unsafe { std::slice::from_raw_parts(result.key, result.length) }.to_vec();
    crate::helpers::free_bytes(result.key);
    key
}

#[test]
fn argon2_derive_aes_key_with_salt_test() {
    type DeriveFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize) -> Argon2DerivedKey;
    let password = b"DoNotUseThisPassword";
    let other_password = b"DoNotUseThisPasswordEither";
    let salt = argon2_generate_salt();
    let salt_bytes = unsafe { std::slice::from_raw_parts(salt.salt, salt.length) }.to_vec();
    let other_salt = [7u8; 16];
    for (derive, key_length) in [
        (argon2_derive_aes_128_key_with_salt as DeriveFn, 16),
        (argon2_derive_aes_256_key_with_salt as DeriveFn, 32),
    ] {
        let key = derived_key_bytes(derive(password.as_ptr(), password.len(), salt_bytes.as_ptr(), salt_bytes.len()));
        let same_salt = derived_key_bytes(derive(password.as_ptr(), password.len(), salt_bytes.as_ptr(), salt_bytes.len()));
        let different_salt = derived_key_bytes(derive(password.as_ptr(), password.len(), other_salt.as_ptr(), other_salt.len()));
        let different_password = derived_key_bytes(derive(other_password.as_ptr(), other_password.len(), salt_bytes.as_ptr(), salt_bytes.len()));
        assert_eq!(key_length, key.len());
        assert_eq!(key, same_salt);
        assert_ne!(key, different_salt);
        assert_ne!(key, different_password);
    }
    crate::helpers::free_bytes(salt.salt);
}

#[test]
fn argon2_derive_aes_key_with_salt_bad_input_test() {
    type DeriveFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize) -> Argon2DerivedKey;
    let invalid_input = cas_error_code(&CasError::InvalidInput);
    let invalid_parameters = cas_error_code(&CasError::InvalidParameters);
    let password = b"DoNotUseThisPassword";
    let salt = [1u8; 16];
    let short_salt = [1u8; 15];
    for derive in [argon2_derive_aes_128_key_with_salt as DeriveFn, argon2_derive_aes_256_key_with_salt as DeriveFn] {
        for (result, expected) in [
            (derive(password.as_ptr(), password.len(), short_salt.as_ptr(), short_salt.len()), invalid_parameters),
            (derive(password.as_ptr(), password.len(), std::ptr::null(), 0), invalid_parameters),
            (derive(password.as_ptr(), password.len(), std::ptr::null(), 16), invalid_input),
            (derive(std::ptr::null(), 8, salt.as_ptr(), salt.len()), invalid_input),
        ] {
            assert!(result.key.is_null());
            assert_eq!(0, result.length);
            assert_eq!(expected, result.error_code);
        }
        // An empty password is valid Argon2 input.
        assert!(!derived_key_bytes(derive(std::ptr::null(), 0, salt.as_ptr(), salt.len())).is_empty());
    }
}

#[cfg(test)]
fn argon2_hash_bytes_value(bytes: &[u8]) -> CString {
    let hash = argon2_hash_password_parameters_bytes(19, 1, 1, bytes.as_ptr(), bytes.len());
    assert_eq!(0, hash.error_code);
    unsafe { CString::from_raw(hash.value) }
}

#[test]
fn argon2_bytes_round_trip_test() {
    let password = b"PasswordToVerify";
    let hash = argon2_hash_bytes(password.as_ptr(), password.len());
    assert_eq!(0, hash.error_code);
    let is_valid = argon2_verify_bytes(hash.value, password.as_ptr(), password.len());
    assert_eq!(0, is_valid.error_code);
    assert!(is_valid.is_valid);
    let is_valid = argon2_verify_bytes(hash.value, password.as_ptr(), password.len() - 1);
    assert_eq!(0, is_valid.error_code);
    assert!(!is_valid.is_valid);
    crate::helpers::free_cstring(hash.value);

    let hash = argon2_hash_bytes_value(password);
    assert!(hash.to_str().unwrap().contains("m=19456,t=1,p=1"));
    assert!(argon2_verify_bytes(hash.as_ptr(), password.as_ptr(), password.len()).is_valid);
}

#[test]
#[allow(deprecated)]
fn argon2_bytes_keeps_embedded_nul_test() {
    let password = b"abc\0def";
    let hash = argon2_hash_bytes_value(password);
    let is_valid = argon2_verify_bytes(hash.as_ptr(), password.as_ptr(), password.len());
    assert!(is_valid.is_valid);
    let is_valid = argon2_verify_bytes(hash.as_ptr(), password.as_ptr(), 3);
    assert_eq!(0, is_valid.error_code);
    assert!(!is_valid.is_valid);
    let prefix = CString::new("abc").unwrap();
    let is_valid = argon2_verify(hash.as_ptr(), prefix.as_ptr());
    assert_eq!(0, is_valid.error_code);
    assert!(!is_valid.is_valid);
}

#[test]
#[allow(deprecated)]
fn argon2_rejects_invalid_utf8_and_null_test() {
    let invalid_input = cas_error_code(&CasError::InvalidInput);
    let invalid_utf8 = [b'a', 0xff, 0xfe, b'b'];
    let invalid_utf8_cstr = CString::new(invalid_utf8.to_vec()).unwrap();
    let hash = argon2_hash_bytes_value(b"DoNotUseThisPassword");

    for result in [
        argon2_hash_bytes(invalid_utf8.as_ptr(), invalid_utf8.len()),
        argon2_hash_password_parameters_bytes(19, 1, 1, invalid_utf8.as_ptr(), invalid_utf8.len()),
        argon2_hash_bytes(std::ptr::null(), 8),
        argon2_hash(invalid_utf8_cstr.as_ptr()),
        argon2_hash(std::ptr::null()),
        argon2_hash_password_parameters(19, 1, 1, invalid_utf8_cstr.as_ptr()),
        argon2_hash_password_parameters(19, 1, 1, std::ptr::null()),
    ] {
        assert!(result.value.is_null());
        assert_eq!(invalid_input, result.error_code);
    }
    for result in [
        argon2_verify_bytes(hash.as_ptr(), invalid_utf8.as_ptr(), invalid_utf8.len()),
        argon2_verify_bytes(hash.as_ptr(), std::ptr::null(), 8),
        argon2_verify_bytes(std::ptr::null(), b"x".as_ptr(), 1),
        argon2_verify_bytes(invalid_utf8_cstr.as_ptr(), b"x".as_ptr(), 1),
        argon2_verify(hash.as_ptr(), invalid_utf8_cstr.as_ptr()),
        argon2_verify(hash.as_ptr(), std::ptr::null()),
        argon2_verify(std::ptr::null(), hash.as_ptr()),
    ] {
        assert!(!result.is_valid);
        assert_eq!(invalid_input, result.error_code);
    }
    for derive in [argon2_derive_aes_128_key, argon2_derive_aes_256_key] {
        let key = derive(std::ptr::null());
        assert!(key.key.is_null());
        assert_eq!(invalid_input, key.error_code);
    }
}
