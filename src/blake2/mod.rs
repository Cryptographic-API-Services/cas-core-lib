use std::ffi::c_uchar;

use cas_lib::hashers::{blake2::CASBlake2, cas_hasher::CASHasher};

mod types;
use self::types::Blake2HashByteResult;
use crate::helpers::export_bytes;
use crate::helpers::CasVerifyResult;
use crate::sha::{input_bytes, verify_digest};

// Algorithms exposed here (cas-lib `CASBlake2`):
// - `blake2_512_bytes` (+ `_verify`): BLAKE2b-512.
// - `blake2_256_bytes` (+ `_verify`): BLAKE2s-256 (not BLAKE2b-256).
//
// Input handling matches the SHA functions: a null pointer is allowed when its length
// is 0, and a null pointer with a non-zero length gives a null `result_bytes_ptr` with
// `length == 0` (hash) or `CasVerifyResult { is_valid: false, error_code: 4 }` (verify)
// instead of a panic. Note the verify argument order: the digest comes first
// (`hashed_data`), then the data it should be the hash of (`to_compare`).

fn into_result(result: Option<Vec<u8>>) -> Blake2HashByteResult {
    let Some(result) = result else {
        return Blake2HashByteResult { result_bytes_ptr: std::ptr::null_mut(), length: 0 };
    };
    let return_result = Blake2HashByteResult {
        result_bytes_ptr: export_bytes(&result),
        length: result.len(),
    };
    return_result
}

#[no_mangle]
pub extern "C" fn blake2_512_bytes(
    data: *const c_uchar,
    data_length: usize,
) -> Blake2HashByteResult {
    into_result(input_bytes(data, data_length).map(<CASBlake2 as CASHasher>::hash_512))
}

#[no_mangle]
pub extern "C" fn blake2_512_bytes_verify(
    hashed_data: *const c_uchar,
    hashed_data_length: usize,
    to_compare: *const c_uchar,
    to_compare_length: usize,
) -> CasVerifyResult {
    verify_digest(
        input_bytes(hashed_data, hashed_data_length),
        input_bytes(to_compare, to_compare_length),
        <CASBlake2 as CASHasher>::verify_512,
    )
}

#[no_mangle]
pub extern "C" fn blake2_256_bytes(
    data_to_hash: *const c_uchar,
    data_to_hash_length: usize,
) -> Blake2HashByteResult {
    into_result(input_bytes(data_to_hash, data_to_hash_length).map(<CASBlake2 as CASHasher>::hash_256))
}

#[no_mangle]
pub extern "C" fn blake2_256_bytes_verify(
    hashed_data: *const c_uchar,
    hashed_data_length: usize,
    to_compare: *const c_uchar,
    to_compare_length: usize,
) -> CasVerifyResult {
    verify_digest(
        input_bytes(hashed_data, hashed_data_length),
        input_bytes(to_compare, to_compare_length),
        <CASBlake2 as CASHasher>::verify_256,
    )
}

// Known-answer tests: RFC 7693 Appendix A ("abc") and the empty-message digests.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::cas_error_code;
    use cas_lib::error::CasError;

    type HashFn = extern "C" fn(*const c_uchar, usize) -> Blake2HashByteResult;
    type VerifyFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize) -> CasVerifyResult;

    const BLAKE2B_512_EMPTY: &str = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce";
    const BLAKE2B_512_ABC: &str = "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923";
    const BLAKE2S_256_EMPTY: &str = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9";
    const BLAKE2S_256_ABC: &str = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982";

    fn to_hex(result: &Blake2HashByteResult) -> String {
        let bytes = unsafe { std::slice::from_raw_parts(result.result_bytes_ptr, result.length) };
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
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

    fn check(hash: HashFn, verify: VerifyFn, empty_hex: &str, abc_hex: &str) {
        let abc = b"abc";

        assert_eq!(to_hex(&hash(abc.as_ptr(), abc.len())), abc_hex);
        assert_eq!(to_hex(&hash(std::ptr::null(), 0)), empty_hex);

        let empty_digest = from_hex(empty_hex);
        let abc_digest = from_hex(abc_hex);
        assert!(valid(verify(abc_digest.as_ptr(), abc_digest.len(), abc.as_ptr(), abc.len())));
        assert!(valid(verify(empty_digest.as_ptr(), empty_digest.len(), std::ptr::null(), 0)));
        assert!(!valid(verify(empty_digest.as_ptr(), empty_digest.len(), abc.as_ptr(), abc.len())));
        assert!(!valid(verify(abc_digest.as_ptr(), abc_digest.len() - 1, abc.as_ptr(), abc.len())));
        assert!(!valid(verify(std::ptr::null(), 0, abc.as_ptr(), abc.len())));

        let null_hash = hash(std::ptr::null(), 3);
        assert!(null_hash.result_bytes_ptr.is_null());
        assert_eq!(0, null_hash.length);
        assert_invalid_input(verify(std::ptr::null(), abc_digest.len(), abc.as_ptr(), abc.len()));
        assert_invalid_input(verify(abc_digest.as_ptr(), abc_digest.len(), std::ptr::null(), 3));
    }

    #[test]
    fn blake2b_512_test() {
        check(blake2_512_bytes, blake2_512_bytes_verify, BLAKE2B_512_EMPTY, BLAKE2B_512_ABC);
    }

    #[test]
    fn blake2s_256_test() {
        check(blake2_256_bytes, blake2_256_bytes_verify, BLAKE2S_256_EMPTY, BLAKE2S_256_ABC);
    }
}
