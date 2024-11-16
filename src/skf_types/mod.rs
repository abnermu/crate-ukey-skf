use std::{ffi::c_void, os::raw::{c_char, c_long}};

// 设备句柄
pub type DEVHANDLE = *mut c_void; 
// 应用句柄
pub type APPLICATIONHANDLE = *mut c_void;
// 容器句柄
pub type CONTAINERHANDLE = *mut c_void;

// c 字符串指针（出参）
pub type LPSTR = *mut c_char;
// c 字符串指针（入参）
pub type SLPSTR = *const c_char;
// c unlong指针（入参）
pub type ULONGPTR = *mut c_long;
// c 字节数组指针（出参）
pub type BYTEPTR = *mut u8;
// c 字节数组指针（入参）
pub type SBYTEPTR = *const u8;