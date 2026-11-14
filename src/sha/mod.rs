use std::ffi::c_uchar;

use cas_lib::hashers::{cas_hasher::CASHasher, sha::CASSHA, sha2::CASSHA2};

use self::types::SHAHashByteResult;
mod types;

// Algorithms exposed here:
// - `sha2_256_bytes` / `sha2_512_bytes` (+ `_verify`): SHA-2 (FIPS 180-4) via cas-lib `CASSHA2`.
// - `sha3_256_bytes` / `sha3_512_bytes` (+ `_verify`): SHA-3 (FIPS 202) via cas-lib `CASSHA`.
// - `sha256_bytes` / `sha512_bytes` (+ `_verify`): legacy names, kept for existing SDK
//   callers. They have always been SHA-3 (cas-lib `CASSHA`) and still are.
//
// Every function accepts empty input: a zero-length buffer hashes as the empty message,
// and a null pointer is allowed when its length is 0.

/// Rebuilds an input buffer from a pointer + length pair.
///
/// Hashing the empty message is valid (it has a well-defined digest), and FFI
/// callers commonly marshal a zero-length array as a null pointer. So a null
/// pointer is accepted when `len == 0`; it is only rejected when `len > 0`.
/// `slice::from_raw_parts` must never be called with a null pointer (even for
/// length 0), hence the early return.
fn input_bytes(ptr: *const c_uchar, len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    assert!(!ptr.is_null());
    unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
}

fn into_result(mut result: Vec<u8>) -> SHAHashByteResult {
    let capacity = result.capacity();
    result.reserve_exact(capacity);
    let return_result = SHAHashByteResult {
        result_bytes_ptr: result.as_mut_ptr(),
        length: result.len(),
    };
    std::mem::forget(result);
    return_result
}

fn hash_256<H: CASHasher>(data_to_hash: *const c_uchar, data_len: usize) -> SHAHashByteResult {
    into_result(H::hash_256(input_bytes(data_to_hash, data_len)))
}

fn hash_512<H: CASHasher>(data_to_hash: *const c_uchar, data_len: usize) -> SHAHashByteResult {
    into_result(H::hash_512(input_bytes(data_to_hash, data_len)))
}

fn verify_256<H: CASHasher>(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> bool {
    let data = input_bytes(data_to_hash, data_len);
    let hash = input_bytes(data_to_verify, data_to_verify_len);
    H::verify_256(hash, data)
}

fn verify_512<H: CASHasher>(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> bool {
    let data = input_bytes(data_to_hash, data_len);
    let hash = input_bytes(data_to_verify, data_to_verify_len);
    H::verify_512(hash, data)
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
) -> bool {
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
) -> bool {
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
) -> bool {
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
) -> bool {
    verify_512::<CASSHA>(data_to_hash, data_len, data_to_verify, data_to_verify_len)
}

// ---- Legacy names (SHA-3) ----

#[no_mangle]
pub extern "C" fn sha512_bytes(data_to_hash: *const c_uchar, data_len: usize) -> SHAHashByteResult {
    hash_512::<CASSHA>(data_to_hash, data_len)
}

#[no_mangle]
pub extern "C" fn sha512_bytes_verify(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> bool {
    verify_512::<CASSHA>(data_to_hash, data_len, data_to_verify, data_to_verify_len)
}

#[no_mangle]
pub extern "C" fn sha256_bytes(data_to_hash: *const c_uchar, data_len: usize) -> SHAHashByteResult {
    hash_256::<CASSHA>(data_to_hash, data_len)
}

#[no_mangle]
pub extern "C" fn sha256_bytes_verify(
    data_to_hash: *const c_uchar,
    data_len: usize,
    data_to_verify: *const c_uchar,
    data_to_verify_len: usize,
) -> bool {
    verify_256::<CASSHA>(data_to_hash, data_len, data_to_verify, data_to_verify_len)
}

// Known-answer tests: FIPS 180-4 (SHA-2) and FIPS 202 (SHA-3) digests of "" and "abc".
#[cfg(test)]
mod tests {
    use super::*;

    type HashFn = extern "C" fn(*const c_uchar, usize) -> SHAHashByteResult;
    type VerifyFn = extern "C" fn(*const c_uchar, usize, *const c_uchar, usize) -> bool;

    const SHA2_256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA2_256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const SHA2_512_EMPTY: &str = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    const SHA2_512_ABC: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    const SHA3_256_EMPTY: &str = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    const SHA3_256_ABC: &str = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
    const SHA3_512_EMPTY: &str = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    const SHA3_512_ABC: &str = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0";

    fn to_hex(result: &SHAHashByteResult) -> String {
        let bytes = unsafe { std::slice::from_raw_parts(result.result_bytes_ptr, result.length) };
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn from_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Checks one algorithm against its "abc" and "" vectors, including a null
    /// pointer with length 0, for both hash and verify.
    fn check(hash: HashFn, verify: VerifyFn, empty_hex: &str, abc_hex: &str) {
        let abc = b"abc";
        let empty: &[u8] = &[];

        assert_eq!(to_hex(&hash(abc.as_ptr(), abc.len())), abc_hex);
        assert_eq!(to_hex(&hash(empty.as_ptr(), 0)), empty_hex);
        assert_eq!(to_hex(&hash(std::ptr::null(), 0)), empty_hex);

        let empty_digest = from_hex(empty_hex);
        let abc_digest = from_hex(abc_hex);
        assert!(verify(abc.as_ptr(), abc.len(), abc_digest.as_ptr(), abc_digest.len()));
        assert!(verify(std::ptr::null(), 0, empty_digest.as_ptr(), empty_digest.len()));
        assert!(!verify(std::ptr::null(), 0, abc_digest.as_ptr(), abc_digest.len()));
        assert!(!verify(abc.as_ptr(), abc.len(), empty_digest.as_ptr(), empty_digest.len()));
    }

    #[test]
    fn sha2_256_test() {
        check(sha2_256_bytes, sha2_256_bytes_verify, SHA2_256_EMPTY, SHA2_256_ABC);
    }

    #[test]
    fn sha2_512_test() {
        check(sha2_512_bytes, sha2_512_bytes_verify, SHA2_512_EMPTY, SHA2_512_ABC);
    }

    #[test]
    fn sha3_256_test() {
        check(sha3_256_bytes, sha3_256_bytes_verify, SHA3_256_EMPTY, SHA3_256_ABC);
    }

    #[test]
    fn sha3_512_test() {
        check(sha3_512_bytes, sha3_512_bytes_verify, SHA3_512_EMPTY, SHA3_512_ABC);
    }

    #[test]
    fn legacy_sha256_is_sha3_test() {
        check(sha256_bytes, sha256_bytes_verify, SHA3_256_EMPTY, SHA3_256_ABC);
    }

    #[test]
    fn legacy_sha512_is_sha3_test() {
        check(sha512_bytes, sha512_bytes_verify, SHA3_512_EMPTY, SHA3_512_ABC);
    }
}
