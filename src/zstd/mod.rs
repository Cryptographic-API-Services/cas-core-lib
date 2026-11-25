use cas_lib::compression::zstd;
use libc::c_uchar;

use crate::helpers::{cas_error_code, export_bytes};

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
        Ok(decompressed_data) => {
            let result = ZstdCompressResult {
                data: export_bytes(&decompressed_data),
                length: decompressed_data.len(),
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

#[no_mangle]
pub extern "C" fn compress(data_to_compress: *const c_uchar, data_to_compress_length: usize, level: usize) -> ZstdCompressResult {
    let data_to_compress = unsafe { std::slice::from_raw_parts(data_to_compress, data_to_compress_length) }.to_vec();
    match zstd::compress(data_to_compress, level as i32) {
        Ok(compressed_data) => {
            let result = ZstdCompressResult {
                data: export_bytes(&compressed_data),
                length: compressed_data.len(),
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