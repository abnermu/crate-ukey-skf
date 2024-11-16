use std::{ffi::CString, os::raw::{c_char, c_long}};
use super::*;

/// 枚举应用结果
pub struct AppEnumResult {
    /// 应用名称列表
    pub sz_app_name: Vec<String>,
    /// 返回结果
    pub result: ErrorDefine,
}
/// 应用打开结果
pub struct AppOpenResult {
    /// 应用名称
    pub sz_app_name: String,
    /// 应用打开句柄
    pub h_app: APPLICATIONHANDLE,
    /// 返回结果
    pub result: ErrorDefine,
}

// 枚举应用
const FN_NAME_SKF_ENUMAPPLICATION: &[u8] = b"SKF_EnumApplication";
type SKFEnumApplication = unsafe extern "C" fn(hDev: DEVHANDLE, szAppName: LPSTR, pulSize: ULONGPTR) -> c_long;
// 打开应用
const FN_NAME_SKF_OPENAPPLICATION: &[u8] = b"SKF_OpenApplication";
type SKFOpenApplication = unsafe extern "C" fn(hDev: DEVHANDLE, szAppName: SLPSTR, phApplication: *mut APPLICATIONHANDLE) -> c_long;
// 关闭应用
const FN_NAME_SKF_CLOSEAPPLICATION: &[u8] = b"SKF_CloseApplication";
type SKFCloseApplication = unsafe extern "C" fn(hApplication: APPLICATIONHANDLE) -> c_long;

/// 应用管理类
pub struct AppManager;
impl AppManager {
    /// 枚举设备中的应用名称
    /// # 参数
    /// - `h_dev` 设备连接句柄
    pub fn list_apps(h_dev: DEVHANDLE) -> Option<AppEnumResult> {
        if let Some(ref fn_enum_app) = unsafe {LibUtil::load_fun_in_dll::<SKFEnumApplication>(FN_NAME_SKF_ENUMAPPLICATION)} {
            let mut sz_app_name_vec: Vec<c_char> = vec![0; 255];
            let sz_app_name: LPSTR = sz_app_name_vec.as_mut_ptr();
            let mut pul_size: c_long = 255;
            let result = unsafe {fn_enum_app(h_dev, sz_app_name, &mut pul_size)};
            return Some(AppEnumResult {
                sz_app_name: if ErrorCodes::is_ok(result) { unsafe {StringUtil::read_strings(sz_app_name, pul_size)} } else { vec![] },
                result: ErrorCodes::get_error(result)
            });
        }
        None
    }
    /// 打开应用
    /// # 参数
    /// - `h_dev` 设备连接句柄
    /// - `app_name` 应用名称
    pub fn open_app(h_dev: DEVHANDLE, app_name: &str) -> Option<AppOpenResult> {
        if let Some(ref fn_enum_app) = unsafe {LibUtil::load_fun_in_dll::<SKFOpenApplication>(FN_NAME_SKF_OPENAPPLICATION)} {
            if let Ok(sz_app_name_cstr) = CString::new(app_name) {
                let sz_app_name: SLPSTR = sz_app_name_cstr.as_ptr();
                let ph_app: *mut APPLICATIONHANDLE = &mut std::ptr::null_mut();
                let result = unsafe {fn_enum_app(h_dev, sz_app_name, ph_app)};
                return Some(AppOpenResult {
                    sz_app_name: app_name.to_string(),
                    h_app: unsafe {*ph_app},
                    result: ErrorCodes::get_error(result),
                });
            }
        }
        None
    }
    /// 关闭应用
    /// # 参数
    /// - `h_app` 应用打开句柄
    pub fn close_app(h_app: APPLICATIONHANDLE) -> Option<ErrorDefine> {
        if let Some(ref fn_close_app) = unsafe {LibUtil::load_fun_in_dll::<SKFCloseApplication>(FN_NAME_SKF_CLOSEAPPLICATION)} {
            let result = unsafe {fn_close_app(h_app)};
            return Some(ErrorCodes::get_error(result));
        }
        None
    }
}