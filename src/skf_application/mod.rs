use std::{ffi::CString, os::raw::{c_char, c_long}};
use log as logger;
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
            let mut sz_app_name_vec: Vec<c_char> = vec![0; LibUtil::LEN_NAMES];
            let mut sz_app_name: LPSTR = sz_app_name_vec.as_mut_ptr();
            let mut pul_size: c_long = LibUtil::LEN_NAMES as c_long;
            let mut result = unsafe {fn_enum_app(h_dev, sz_app_name, &mut pul_size)};
            if !ErrorCodes::is_ok(result) && pul_size > LibUtil::LEN_NAMES as c_long {
                sz_app_name_vec = vec![0; pul_size as usize];
                sz_app_name = sz_app_name_vec.as_mut_ptr();
                result = unsafe {fn_enum_app(h_dev, sz_app_name, &mut pul_size)};
            }
            return Some(AppEnumResult {
                sz_app_name: if ErrorCodes::is_ok(result) { unsafe {jyframe::StringUtil::read_c_strings(sz_app_name, pul_size)} } else { vec![] },
                result: ErrorCodes::get_error(result)
            });
        }
        else {
            logger::warn!("load list applications function failed");
        }
        None
    }
    /// 打开应用
    /// # 参数
    /// - `h_dev` 设备连接句柄
    /// - `app_name` 应用名称
    pub fn open_app(h_dev: DEVHANDLE, app_name: &str) -> Option<AppOpenResult> {
        if let Some(ref fn_enum_app) = unsafe {LibUtil::load_fun_in_dll::<SKFOpenApplication>(FN_NAME_SKF_OPENAPPLICATION)} {
            match CString::new(app_name) {
                Ok(sz_app_name_cstr) => {
                    let sz_app_name: SLPSTR = sz_app_name_cstr.as_ptr();
                    let ph_app: *mut APPLICATIONHANDLE = &mut std::ptr::null_mut();
                    let result = unsafe {fn_enum_app(h_dev, sz_app_name, ph_app)};
                    return Some(AppOpenResult {
                        sz_app_name: app_name.to_string(),
                        h_app: unsafe {*ph_app},
                        result: ErrorCodes::get_error(result),
                    });
                },
                Err(err) => {
                    logger::error!("error occured when convert the application name to c-string: {}", err);
                }
            }
        }
        else {
            logger::warn!("load open application function failed");
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
        else {
            logger::warn!("load close application function failed");
        }
        None
    }
    
    // pub fn get_app_available(h_dev: DEVHANDLE) -> Option<(String, APPLICATIONHANDLE)> {
    //     // 第一步枚举应用
    //     if let Some(app_list) = AppManager::list_apps(h_dev.clone()) {
    //         if app_list.result.is_ok() && app_list.sz_app_name.len() > 0 {
    //             // 第二步打开应用
    //             if let Some(app_opener) = AppManager::open_app(h_dev.clone(), &app_list.sz_app_name[0]) {
    //                 return if app_opener.result.is_ok() {Some(((&app_list.sz_app_name[0]).to_string(), app_opener.h_app.clone()))} else {None};
    //             }
    //             else {
    //                 logger::warn!("open application with name[{}] failed", &app_list.sz_app_name[0]);
    //             }
    //         }
    //         else {
    //             logger::warn!("there is no avalilable application to open");
    //         }
    //     }
    //     else {
    //         logger::warn!("list availiable applications failed");
    //     }
    //     None
    // }
}