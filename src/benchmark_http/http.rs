use std::ffi::CStr;
use libc::c_char;

use cas_lib::http::{send_benchmark, set_api_key_in_cache, set_base_url_in_cache, set_tokens_in_cache, types::runtime::RUNTIME};


#[no_mangle]
pub extern "C" fn set_base_url(base_url: *const c_char) {
    let base_url_string = unsafe {
        assert!(!base_url.is_null());
        CStr::from_ptr(base_url)
    }
    .to_str()
    .unwrap()
    .to_string();
    set_base_url_in_cache(base_url_string);
}

#[no_mangle]
pub extern "C" fn set_api_key(api_key: *const c_char) {
    let api_key_string = unsafe {
        assert!(!api_key.is_null());
        CStr::from_ptr(api_key)
    }
    .to_str()
    .unwrap()
    .to_string();
    RUNTIME.block_on(set_api_key_in_cache(api_key_string));
}

#[no_mangle]
pub extern "C" fn send_benchmark_to_api(time_in_milliseconds: i64, class_name: *const c_char, method_name: *const c_char) {
    let class_name_string = unsafe {
        assert!(!class_name.is_null());
        CStr::from_ptr(class_name)
    }
    .to_str()
    .unwrap()
    .to_string();
    let method_name_string = unsafe {
        assert!(!method_name.is_null());
        CStr::from_ptr(method_name)
    }
    .to_str()
    .unwrap()
    .to_string();

    let class_name_for_async = class_name_string.clone();
    let method_name_for_async = method_name_string.clone();
    RUNTIME.spawn(async move {
        send_benchmark(time_in_milliseconds, class_name_for_async, method_name_for_async).await;
    });
}