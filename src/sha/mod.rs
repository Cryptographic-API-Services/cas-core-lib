use std::ffi::c_uchar;

use cas_lib::error::CasError;
use cas_lib::hashers::{cas_hasher::CASHasher, sha::CASSHA, sha2::CASSHA2};

use self::types::SHAHashByteResult;
use crate::helpers::export_bytes;
use crate::helpers::{cas_error_code, CasVerifyResult};
mod types;

// Algorithms exposed here:
// - `sha2_256_bytes` / `sha2_512_bytes` (+ `_verify`): SHA-2 (FIPS 180-4) via cas-lib `CASSHA2`.
// - `sha3_256_bytes` / `sha3_512_bytes` (+ `_verify`): SHA-3 (FIPS 202) via cas-lib `CASSHA`.
// - `sha256_bytes` / `sha512_bytes` (+ `_verify`): deprecated legacy names, kept for
//   existing SDK callers. They have always been SHA-3 (cas-lib `CASSHA`) and still are;
//   they are thin aliases of the `sha3_*` functions.
//
// Every function accepts empty input: a zero-length buffer hashes as the empty message,
// and a null pointer is allowed when its length is 0. A null pointer with a non-zero
// length is invalid input and never panics across the FFI: the hash functions return a
// null `result_bytes_ptr` with `length == 0` (a real digest is never empty), and the
// verify functions return `CasVerifyResult { is_valid: false, error_code: 4 }`
// (`CasError::InvalidInput`).
//
// Verification delegates to cas-lib's `CASHasher::verify_*`, which compares the digests
// in constant time (`subtle::ConstantTimeEq`) from cas-lib 0.3.0 on.

/// Rebuilds an input buffer from a pointer + length pair, or `None` if the
/// pointer is null while `len > 0`.
///
/// Hashing the empty message is valid (it has a well-defined digest), and FFI
/// callers commonly marshal a zero-length array as a null pointer. So a null
/// pointer is accepted when `len == 0`; it is only rejected when `len > 0`.
/// `slice::from_raw_parts` must never be called with a null pointer (even for
/// length 0), hence the early return.
pub(crate) fn input_bytes(ptr: *const c_uchar, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec())
}

/// Runs a cas-lib verify on a digest and the data it should be the hash of,
/// reporting a null pointer with a non-zero length as `InvalidInput`.
pub(crate) fn verify_digest(
    digest: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
    verify: fn(Vec<u8>, Vec<u8>) -> bool,
) -> CasVerifyResult {
    match (digest, data) {
        (Some(digest), Some(data)) => CasVerifyResult { is_valid: verify(digest, data), error_code: 0 },
        _ => CasVerifyResult { is_valid: false, error_code: cas_error_code(&CasError::InvalidInput) },
    }
}

fn into_result(result: Option<Vec<u8>>) -> SHAHashByteResult {
    let Some(result) = result else {
        return SHAHashByteResult { result_bytes_ptr: std::ptr::null_mut(), length: 0 };
    };
    let return_result = SHAHashByteResult {
        result_bytes_ptr: export_bytes(&result),
        length: result.len(),
    };
    return_result
}

fn hash_256<H: CASHasher>(data_to_hash: *const c_uchar, data_len: usize) -> SHAHashByteResult {
    into_result(input_bytes(data_to_hash, data_len).map(H::hash_256))
}

fn hash_512<H: CASHasher>(data_to_hash: *const c_uchar, data_len: usize) -> SHAHashByteResult {
    into_result(input_bytes(data_to_hash, data_len).map(H::hash_512))
}

fn verify_256<H: CASHasher>(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> CasVerifyResult {
    verify_digest(
        input_bytes(data_to_verify, data_to_verify_len),
        input_bytes(data_to_hash, data_len),
        H::verify_256,
    )
}

fn verify_512<H: CASHasher>(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> CasVerifyResult {
    verify_digest(
        input_bytes(data_to_verify, data_to_verify_len),
        input_bytes(data_to_hash, data_len),
        H::verify_512,
    )
}

// ---- SHA-2 ----

#[no_mangle]
pub extern "C" fn sha2_256_bytes(data_to_hash: *const c_uchar, data_len: usize) -> SHAHashByteResult {
    hash_256::<CASSHA2>(data_to_hash, data_len)
}

#[no_mangle]
pub extern "C" fn sha2_256_bytes_verify(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> CasVerifyResult {
    verify_256::<CASSHA2>(data_to_hash, data_len, data_to_verify, data_to_verify_len)
}

#[no_mangle]
pub extern "C" fn sha2_512_bytes(data_to_hash: *const c_uchar, data_len: usize) -> SHAHashByteResult {
    hash_512::<CASSHA2>(data_to_hash, data_len)
}

#[no_mangle]
pub extern "C" fn sha2_512_bytes_verify(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> CasVerifyResult {
    verify_512::<CASSHA2>(data_to_hash, data_len, data_to_verify, data_to_verify_len)
}

// ---- SHA-3 ----

#[no_mangle]
pub extern "C" fn sha3_256_bytes(data_to_hash: *const c_uchar, data_len: usize) -> SHAHashByteResult {
    hash_256::<CASSHA>(data_to_hash, data_len)
}

#[no_mangle]
pub extern "C" fn sha3_256_bytes_verify(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> CasVerifyResult {
    verify_256::<CASSHA>(data_to_hash, data_len, data_to_verify, data_to_verify_len)
}

#[no_mangle]
pub extern "C" fn sha3_512_bytes(data_to_hash: *const c_uchar, data_len: usize) -> SHAHashByteResult {
    hash_512::<CASSHA>(data_to_hash, data_len)
}

#[no_mangle]
pub extern "C" fn sha3_512_bytes_verify(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> CasVerifyResult {
    verify_512::<CASSHA>(data_to_hash, data_len, data_to_verify, data_to_verify_len)
}

// ---- Legacy names (SHA-3) ----
//
// These four symbols predate the explicit `sha2_*` / `sha3_*` names. Despite the
// names they have always computed SHA-3, and existing callers (cas-dotnet-sdk's
// `SHAWrapper`) store and compare SHA-3 digests through them, so they stay SHA-3
// aliases rather than silently switching to SHA-2. Do not add new callers: use
// `sha3_*` for the same output, or `sha2_*` for real SHA-256 / SHA-512.

/// Deprecated alias of [`sha3_512_bytes`]: computes SHA3-512, not SHA-512.
#[deprecated(note = "computes SHA3-512; call sha3_512_bytes (or sha2_512_bytes for SHA-512)")]
#[no_mangle]
pub extern "C" fn sha512_bytes(data_to_hash: *const c_uchar, data_len: usize) -> SHAHashByteResult {
    sha3_512_bytes(data_to_hash, data_len)
}

/// Deprecated alias of [`sha3_512_bytes_verify`]: verifies a SHA3-512 digest, not SHA-512.
#[deprecated(note = "verifies SHA3-512; call sha3_512_bytes_verify (or sha2_512_bytes_verify for SHA-512)")]
#[no_mangle]
pub extern "C" fn sha512_bytes_verify(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> CasVerifyResult {
    sha3_512_bytes_verify(data_to_hash, data_len, data_to_verify, data_to_verify_len)
}

/// Deprecated alias of [`sha3_256_bytes`]: computes SHA3-256, not SHA-256.
#[deprecated(note = "computes SHA3-256; call sha3_256_bytes (or sha2_256_bytes for SHA-256)")]
#[no_mangle]
pub extern "C" fn sha256_bytes(data_to_hash: *const c_uchar, data_len: usize) -> SHAHashByteResult {
    sha3_256_bytes(data_to_hash, data_len)
}

/// Deprecated alias of [`sha3_256_bytes_verify`]: verifies a SHA3-256 digest, not SHA-256.
#[deprecated(note = "verifies SHA3-256; call sha3_256_bytes_verify (or sha2_256_bytes_verify for SHA-256)")]
#[no_mangle]
pub extern "C" fn sha256_bytes_verify(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> CasVerifyResult {
    sha3_256_bytes_verify(data_to_hash, data_len, data_to_verify, data_to_verify_len)
}

// Known-answer tests: FIPS 180-4 (SHA-2) and FIPS 202 (SHA-3) digests of "", "abc" and
// the 448-bit two-block message "abcdbcdecdef...nopq" (NIST CSRC example values).
#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    type HashFn = extern "C" fn(*const c_uchar, usize) -> SHAHashByteResult;
    type VerifyFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize) -> CasVerifyResult;

    const SHA2_256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA2_256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const SHA2_512_EMPTY: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    const SHA2_512_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    const SHA3_256_EMPTY: &str = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    const SHA3_256_ABC: &str = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
    const SHA3_512_EMPTY: &str = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    const SHA3_512_ABC: &str = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0";

    const MSG_448: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const SHA2_256_448: &str = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    const SHA2_512_448: &str = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445";
    const SHA3_256_448: &str = "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376";
    const SHA3_512_448: &str = "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e";

    fn to_hex(result: &SHAHashByteResult) -> String {
        let bytes = unsafe { std::slice::from_raw_parts(result.result_bytes_ptr, result.length) };
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Unwraps a verify result that must not have reported an error.
    fn valid(result: CasVerifyResult) -> bool {
        assert_eq!(0, result.error_code);
        result.is_valid
    }

    fn assert_invalid_input(result: CasVerifyResult) {
        assert!(!result.is_valid);
        assert_eq!(cas_error_code(&CasError::InvalidInput), result.error_code);
    }

    fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Checks one algorithm against its "", "abc" and 448-bit vectors, including a
    /// null pointer with length 0, for both hash and verify.
    fn check(hash: HashFn, verify: VerifyFn, empty_hex: &str, abc_hex: &str, msg_448_hex: &str) {
        let abc = b"abc";
        let empty: &[u8] = &[];

        assert_eq!(to_hex(&hash(abc.as_ptr(), abc.len())), abc_hex);
        assert_eq!(to_hex(&hash(MSG_448.as_ptr(), MSG_448.len())), msg_448_hex);
        assert_eq!(to_hex(&hash(empty.as_ptr(), 0)), empty_hex);
        assert_eq!(to_hex(&hash(std::ptr::null(), 0)), empty_hex);

        let empty_digest = from_hex(empty_hex);
        let abc_digest = from_hex(abc_hex);
        let msg_448_digest = from_hex(msg_448_hex);
        assert!(valid(verify(abc.as_ptr(), abc.len(), abc_digest.as_ptr(), abc_digest.len())));
        assert!(valid(verify(MSG_448.as_ptr(), MSG_448.len(), msg_448_digest.as_ptr(), msg_448_digest.len())));
        assert!(valid(verify(std::ptr::null(), 0, empty_digest.as_ptr(), empty_digest.len())));
        assert!(!valid(verify(std::ptr::null(), 0, abc_digest.as_ptr(), abc_digest.len())));
        assert!(!valid(verify(abc.as_ptr(), abc.len(), empty_digest.as_ptr(), empty_digest.len())));
        // Truncated digest and empty digest: a mismatch, not an error.
        assert!(!valid(verify(abc.as_ptr(), abc.len(), abc_digest.as_ptr(), abc_digest.len() - 1)));
        assert!(!valid(verify(abc.as_ptr(), abc.len(), std::ptr::null(), 0)));

        // A null pointer with a non-zero length is reported, not a panic.
        let null_hash = hash(std::ptr::null(), 3);
        assert!(null_hash.result_bytes_ptr.is_null());
        assert_eq!(0, null_hash.length);
        assert_invalid_input(verify(std::ptr::null(), 3, abc_digest.as_ptr(), abc_digest.len()));
        assert_invalid_input(verify(abc.as_ptr(), abc.len(), std::ptr::null(), abc_digest.len()));
    }

    #[test]
    fn sha2_256_test() {
        check(sha2_256_bytes, sha2_256_bytes_verify, SHA2_256_EMPTY, SHA2_256_ABC, SHA2_256_448);
    }

    #[test]
    fn sha2_512_test() {
        check(sha2_512_bytes, sha2_512_bytes_verify, SHA2_512_EMPTY, SHA2_512_ABC, SHA2_512_448);
    }

    #[test]
    fn sha3_256_test() {
        check(sha3_256_bytes, sha3_256_bytes_verify, SHA3_256_EMPTY, SHA3_256_ABC, SHA3_256_448);
    }

    #[test]
    fn sha3_512_test() {
        check(sha3_512_bytes, sha3_512_bytes_verify, SHA3_512_EMPTY, SHA3_512_ABC, SHA3_512_448);
    }

    // The legacy names must keep producing SHA-3: SDK callers have stored digests
    // made with them. These also pin that they are *not* SHA-2.
    #[test]
    fn legacy_sha256_is_sha3_test() {
        check(sha256_bytes, sha256_bytes_verify, SHA3_256_EMPTY, SHA3_256_ABC, SHA3_256_448);
    }

    #[test]
    fn legacy_sha512_is_sha3_test() {
        check(sha512_bytes, sha512_bytes_verify, SHA3_512_EMPTY, SHA3_512_ABC, SHA3_512_448);
    }

    #[test]
    fn legacy_names_are_not_sha2_test() {
        let abc = b"abc";
        assert_ne!(to_hex(&sha256_bytes(abc.as_ptr(), abc.len())), SHA2_256_ABC);
        assert_ne!(to_hex(&sha512_bytes(abc.as_ptr(), abc.len())), SHA2_512_ABC);
        let sha2_256 = from_hex(SHA2_256_ABC);
        let sha2_512 = from_hex(SHA2_512_ABC);
        assert!(!valid(sha256_bytes_verify(abc.as_ptr(), abc.len(), sha2_256.as_ptr(), sha2_256.len())));
        assert!(!valid(sha512_bytes_verify(abc.as_ptr(), abc.len(), sha2_512.as_ptr(), sha2_512.len())));
    }
}
