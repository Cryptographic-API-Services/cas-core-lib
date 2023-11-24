// ZSTD is not a encryption algorithm. It is a compression algorithm.
// https://github.com/facebook/zstd
// https://github.com/gyscos/zstd-rs

use std::ffi::{c_char, CStr, CString};
use std::io::{Read, Write};
use std::ptr;
use zstd::{stream::Decoder, stream::Encoder};

use crate::helpers::free_bytes_vector;

#[repr(C)]
pub struct ZstdCompressedBytes {
    pub raw_ptr: *mut u8,
    pub length: usize,
}


#[repr(C)]
pub struct ZstdDecompressedBytes {
    pub raw_ptr: *mut u8,
    pub length: usize,
}

#[no_mangle]
pub extern "C" fn zstd_compress(data: *const c_char, level: i32) -> *mut c_char {
    let data_bytes = unsafe {
        assert!(!data.is_null());
        CStr::from_ptr(data)
    }
    .to_str()
    .unwrap()
    .as_bytes();

    let mut encoder = Encoder::new(Vec::new(), level).unwrap();
    encoder.write_all(data_bytes).unwrap();
    let compressed_data = encoder.finish().unwrap();
    return CString::new(base64::encode(compressed_data))
        .unwrap()
        .into_raw();
}

#[no_mangle]
pub extern "C" fn zstd_compress_bytes(data: *const u8, length: usize, level: i32) -> ZstdCompressedBytes {
    unsafe {
        let slice = std::slice::from_raw_parts(data, length);
        let mut encoder = Encoder::new(Vec::new(), level).unwrap();
        encoder.write_all(slice).unwrap();
        let compressed_data = encoder.finish().unwrap();
        let length = compressed_data.len();
        let raw_ptr = {
            let ptr = libc::malloc(length) as *mut u8;
            if ptr.is_null() {
                panic!("Failed to allocate memory");
            }
            ptr::copy_nonoverlapping(compressed_data.as_ptr(), ptr, length);
            ptr
        };
        let compressed_bytes = ZstdCompressedBytes {
            raw_ptr: raw_ptr,
            length: length,
        };
        return compressed_bytes;
    }
}

#[test]
fn zstd_compress_test() {
    let data_to_compress = "Hello World";
    let data_to_compress_ptr = CString::new(data_to_compress).unwrap().into_raw();
    let result = zstd_compress(data_to_compress_ptr, 3);
    let result_string = unsafe { CStr::from_ptr(result) }.to_str().unwrap();
    assert_ne!(data_to_compress, result_string);
}

#[test]
fn zstd_compress_bytes_test() {
    let data_to_compress = b"Hello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello World";
    let data_to_compress_ptr = data_to_compress.as_ptr();
    let length = data_to_compress.len();
    let compressed_bytes: ZstdCompressedBytes = zstd_compress_bytes(data_to_compress_ptr, length, 3);
    assert!(compressed_bytes.length < length);
    free_bytes_vector(compressed_bytes.raw_ptr);
}

#[no_mangle]
pub extern "C" fn zstd_decompress(data: *const c_char) -> *mut c_char {
    let data_bytes = unsafe {
        assert!(!data.is_null());
        CStr::from_ptr(data)
    }
    .to_str()
    .unwrap();
    let binding = base64::decode(data_bytes).unwrap();
    let decoded_data = binding.as_slice();
    let mut decoder = Decoder::new(decoded_data).unwrap();
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data).unwrap();
    return CString::new(decompressed_data).unwrap().into_raw();
}

#[test]
fn zstd_decompress_bytes_test() {
    let data_to_compress = b"Hello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello WorldHello World";
    let data_to_compress_ptr = data_to_compress.as_ptr();
    let length = data_to_compress.len();
    let compressed_bytes: ZstdCompressedBytes = zstd_compress_bytes(data_to_compress_ptr, length, 3);
    let decompressed_bytes: ZstdDecompressedBytes = zstd_decompress_bytes(compressed_bytes.raw_ptr, compressed_bytes.length);
    assert_eq!(length, decompressed_bytes.length);
    free_bytes_vector(compressed_bytes.raw_ptr);
    free_bytes_vector(decompressed_bytes.raw_ptr);
}


#[no_mangle]
pub extern "C" fn zstd_decompress_bytes(data: *const u8, length: usize) -> ZstdDecompressedBytes {
    unsafe {
        let slice = std::slice::from_raw_parts(data, length);
        let mut decoder = Decoder::new(slice).unwrap();
        let mut decompressed_data = Vec::new();
        decoder.read_to_end(&mut decompressed_data).unwrap();
        let length = decompressed_data.len();
        let raw_ptr = {
            let ptr = libc::malloc(length) as *mut u8;
            if ptr.is_null() {
                panic!("Failed to allocate memory");
            }
            ptr::copy_nonoverlapping(decompressed_data.as_ptr(), ptr, length);
            ptr
        };
        let decompressed_result = ZstdDecompressedBytes {
            raw_ptr: raw_ptr,
            length: length,
        };
        return decompressed_result;
    }
}

#[test]
fn zstd_decompress_test() {
    let data_to_compress = "Hello World";
    let data_to_compress_ptr = CString::new(data_to_compress).unwrap().into_raw();
    let result = zstd_compress(data_to_compress_ptr, 3);
    let decompress_result = zstd_decompress(result);
    let decompress_result_string = unsafe { CStr::from_ptr(decompress_result) }
        .to_str()
        .unwrap();
    assert_eq!(data_to_compress, decompress_result_string);
}
