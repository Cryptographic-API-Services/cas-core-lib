use cas_lib::compression::zstd;
use cas_lib::error::{CasError, CasResult};
use libc::c_uchar;

use crate::helpers::{cas_error_code, export_bytes};

/// Highest zstd compression level. Callers pass `level` as a `usize`, so the
/// accepted range is `0..=MAX_COMPRESSION_LEVEL` (0 selects zstd's default).
const MAX_COMPRESSION_LEVEL: usize = 22;

/// Output of `compress` / `decompress` / `decompress_with_limit`.
///
/// The caller owns `data` and frees it once with `free_bytes`. It is
/// null when `error_code` is non-zero.
#[repr(C)]
pub struct ZstdCompressResult {
    data: *mut c_uchar,
    length: usize,
    error_code: i32,
}

/// Hands a cas-lib result to the caller as a `ZstdCompressResult`, copying the
/// buffer out with `export_bytes` on success (freed with `free_bytes`) and
/// setting `error_code` on failure.
fn to_ffi_result(result: CasResult<Vec<u8>>) -> ZstdCompressResult {
    match result {
        Ok(data) => {
            let result = ZstdCompressResult {
                data: export_bytes(&data),
                length: data.len(),
                error_code: 0,
            };
            result
        }
        Err(e) => ZstdCompressResult {
            data: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

/// Decompresses zstd data, producing at most 64 MiB of output
/// (cas-lib's `DEFAULT_MAX_DECOMPRESSED_SIZE`).
///
/// Larger output returns `error_code = 13` (`DecompressionLimitExceeded`); use
/// [`decompress_with_limit`] to choose a different cap.
#[no_mangle]
pub extern "C" fn decompress(data_to_decompress: *const c_uchar, data_to_decompress_length: usize) -> ZstdCompressResult {
    let data_to_decompress = unsafe { std::slice::from_raw_parts(data_to_decompress, data_to_decompress_length) }.to_vec();
    to_ffi_result(zstd::decompress(data_to_decompress))
}

/// Decompresses zstd data, producing at most `max_output_length` bytes.
///
/// Output larger than `max_output_length` returns `error_code = 13`
/// (`DecompressionLimitExceeded`). A `max_output_length` of 0 returns
/// `error_code = 6` (`InvalidParameters`).
#[no_mangle]
pub extern "C" fn decompress_with_limit(
    data_to_decompress: *const c_uchar,
    data_to_decompress_length: usize,
    max_output_length: usize,
) -> ZstdCompressResult {
    if max_output_length == 0 {
        return to_ffi_result(Err(CasError::InvalidParameters));
    }
    let data_to_decompress = unsafe { std::slice::from_raw_parts(data_to_decompress, data_to_decompress_length) }.to_vec();
    to_ffi_result(zstd::decompress_with_limit(data_to_decompress, max_output_length))
}

/// Compresses data with zstd. `level` must be in `0..=22` (0 selects zstd's
/// default); anything else returns `error_code = 6` (`InvalidParameters`).
#[no_mangle]
pub extern "C" fn compress(data_to_compress: *const c_uchar, data_to_compress_length: usize, level: usize) -> ZstdCompressResult {
    if level > MAX_COMPRESSION_LEVEL {
        return to_ffi_result(Err(CasError::InvalidParameters));
    }
    let data_to_compress = unsafe { std::slice::from_raw_parts(data_to_compress, data_to_compress_length) }.to_vec();
    to_ffi_result(zstd::compress(data_to_compress, level as i32))
}

#[cfg(test)]
fn take_bytes(result: &ZstdCompressResult) -> Vec<u8> {
    assert_eq!(0, result.error_code);
    unsafe { std::slice::from_raw_parts(result.data, result.length) }.to_vec()
}

#[cfg(test)]
const MIB: usize = 1024 * 1024;

#[test]
fn compress_decompress_test() {
    let data = b"This is some data to compress and decompress using zstd.".to_vec();
    let compressed = take_bytes(&compress(data.as_ptr(), data.len(), 3));
    let decompressed = take_bytes(&decompress(compressed.as_ptr(), compressed.len()));
    assert_eq!(data, decompressed);
    let decompressed = take_bytes(&decompress_with_limit(compressed.as_ptr(), compressed.len(), data.len()));
    assert_eq!(data, decompressed);
}

#[test]
fn compress_level_range_test() {
    let data = vec![7u8; 1024];
    for level in [0, 1, MAX_COMPRESSION_LEVEL] {
        let compressed = take_bytes(&compress(data.as_ptr(), data.len(), level));
        assert_eq!(data, take_bytes(&decompress(compressed.as_ptr(), compressed.len())));
    }
    // Values that used to wrap to a negative i32 level are rejected.
    for level in [MAX_COMPRESSION_LEVEL + 1, i32::MAX as usize + 1, usize::MAX] {
        let result = compress(data.as_ptr(), data.len(), level);
        assert!(result.data.is_null());
        assert_eq!(0, result.length);
        assert_eq!(cas_error_code(&CasError::InvalidParameters), result.error_code);
    }
}

#[test]
fn decompress_with_limit_bomb_test() {
    // 1 MiB of zeros compresses to a few dozen bytes: a small bomb against a 4 KiB limit.
    let data = vec![0u8; MIB];
    let bomb = take_bytes(&compress(data.as_ptr(), data.len(), 19));
    assert!(bomb.len() < 1024);
    let result = decompress_with_limit(bomb.as_ptr(), bomb.len(), 4096);
    assert!(result.data.is_null());
    assert_eq!(0, result.length);
    assert_eq!(13, result.error_code);
    assert_eq!(cas_error_code(&CasError::DecompressionLimitExceeded), result.error_code);
}

#[test]
fn decompress_with_limit_boundary_test() {
    let data = vec![0u8; 1024];
    let compressed = take_bytes(&compress(data.as_ptr(), data.len(), 3));
    let result = decompress_with_limit(compressed.as_ptr(), compressed.len(), 1023);
    assert_eq!(cas_error_code(&CasError::DecompressionLimitExceeded), result.error_code);
    assert_eq!(data, take_bytes(&decompress_with_limit(compressed.as_ptr(), compressed.len(), 1024)));
}

#[test]
fn decompress_with_zero_limit_test() {
    let data = vec![0u8; 16];
    let compressed = take_bytes(&compress(data.as_ptr(), data.len(), 3));
    let result = decompress_with_limit(compressed.as_ptr(), compressed.len(), 0);
    assert!(result.data.is_null());
    assert_eq!(cas_error_code(&CasError::InvalidParameters), result.error_code);
}

#[test]
fn decompress_default_limit_test() {
    let data = vec![0u8; 65 * MIB];
    let compressed = take_bytes(&compress(data.as_ptr(), data.len(), 3));
    assert!(compressed.len() < MIB);
    let result = decompress(compressed.as_ptr(), compressed.len());
    assert!(result.data.is_null());
    assert_eq!(cas_error_code(&CasError::DecompressionLimitExceeded), result.error_code);
    let decompressed = take_bytes(&decompress_with_limit(compressed.as_ptr(), compressed.len(), 70 * MIB));
    assert_eq!(data.len(), decompressed.len());
    assert!(decompressed.iter().all(|byte| *byte == 0));
}

#[test]
fn decompress_invalid_data_test() {
    let data = b"not zstd data".to_vec();
    let result = decompress(data.as_ptr(), data.len());
    assert!(result.data.is_null());
    assert_eq!(cas_error_code(&CasError::CompressionFailed), result.error_code);
}
