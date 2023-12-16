use std::ffi::{c_char, c_uchar, c_void, CString};

#[no_mangle]
pub extern "C" fn free_cstring(s: *mut c_char) {
    unsafe {
        if s.is_null() {
            return;
        }
        CString::from_raw(s)
    };
}

#[no_mangle]
pub extern "C" fn free_bytes(ptr: *mut c_uchar) {
    unsafe {
        libc::free(ptr as *mut c_void);
    }
}
