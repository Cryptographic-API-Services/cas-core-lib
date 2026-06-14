use cas_lib::compression::zstd;
use libc::c_uchar;

use crate::helpers::cas_error_code;

#[repr(C)]
pub struct ZstdCompressResult {
    data: *mut c_uchar,
    length: usize,
    error_code: i32,
}

#[no_mangle]
pub extern "C" fn decompress(data_to_decompress: *const c_uchar, data_to_decompress_length: usize) -> ZstdCompressResult {
    let data_to_decompress = unsafe { std::slice::from_raw_parts(data_to_decompress, data_to_decompress_length) }.to_vec();
    match zstd::decompress(data_to_decompress) {
        Ok(mut decompressed_data) => {
            let capacity = decompressed_data.capacity();
            decompressed_data.reserve_exact(capacity);
            let result = ZstdCompressResult {
                data: decompressed_data.as_mut_ptr(),
                length: decompressed_data.len(),
                error_code: 0,
            };
            std::mem::forget(decompressed_data);
            result
        }
        Err(e) => ZstdCompressResult {
            data: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}

#[no_mangle]
pub extern "C" fn compress(data_to_compress: *const c_uchar, data_to_compress_length: usize, level: usize) -> ZstdCompressResult {
    let data_to_compress = unsafe { std::slice::from_raw_parts(data_to_compress, data_to_compress_length) }.to_vec();
    match zstd::compress(data_to_compress, level as i32) {
        Ok(mut compressed_data) => {
            let capacity = compressed_data.capacity();
            compressed_data.reserve_exact(capacity);
            let result = ZstdCompressResult {
                data: compressed_data.as_mut_ptr(),
                length: compressed_data.len(),
                error_code: 0,
            };
            std::mem::forget(compressed_data);
            result
        }
        Err(e) => ZstdCompressResult {
            data: std::ptr::null_mut(),
            length: 0,
            error_code: cas_error_code(&e),
        },
    }
}