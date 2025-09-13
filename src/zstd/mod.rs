use cas_lib::compression::zstd;
use libc::c_uchar;

#[repr(C)]
pub struct ZstdCompressResult {
    data: *mut c_uchar,
    length: usize
}

#[no_mangle]
pub extern "C" fn decompress(data_to_decompress: *const c_uchar, data_to_decompress_length: usize) -> ZstdCompressResult {
    let data_to_decompress = unsafe { std::slice::from_raw_parts(data_to_decompress, data_to_decompress_length) }.to_vec();
    let mut decompressed_data = zstd::decompress(data_to_decompress);
    let capacity = decompressed_data.capacity();
    decompressed_data.reserve_exact(capacity);
    let result = ZstdCompressResult {
        data: decompressed_data.as_mut_ptr(),
        length: decompressed_data.len()
    };
    std::mem::forget(decompressed_data);
    result
}

#[no_mangle]
pub extern "C" fn compress(data_to_compress: *const c_uchar, data_to_compress_length: usize, level: usize) -> ZstdCompressResult {
    let data_to_compress = unsafe { std::slice::from_raw_parts(data_to_compress, data_to_compress_length) }.to_vec();
    let mut compressed_data = zstd::compress(data_to_compress, level as i32);
    let capacity = compressed_data.capacity();
    compressed_data.reserve_exact(capacity);
    let result = ZstdCompressResult {
        data: compressed_data.as_mut_ptr(),
        length: compressed_data.len()
    };
    std::mem::forget(compressed_data);
    result
}