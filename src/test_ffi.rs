use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
};

#[no_mangle]
pub extern "C" fn increment(i: i32) -> i32 {
    i + 1
}

#[no_mangle]
pub extern "C" fn to_cstring(num: i32) -> *mut c_char {
    CString::new(num.to_string()).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn free_cstring(num_cstr: *mut c_char) -> i32 {
    let cstr = unsafe { CString::from_raw(num_cstr) };
    cstr.to_str().unwrap().parse().unwrap()
}

#[no_mangle]
pub extern "C" fn print_cstring(text: *const c_char) {
    let cstr = unsafe { CStr::from_ptr(text) };
    let str = cstr.to_str().unwrap();
    println!("Text: {}", str);
}
