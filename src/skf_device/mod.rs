use std::{ffi::CString, os::raw::{c_long, c_char, c_int}};
use log as logger;
use super::*;

/// 等待插拔事件类型
#[derive(PartialEq)]
pub enum WaitEvent {
    /// `1` 设备插入
    DEVIN,
    /// `2` 设备拔出
    DEVOUT,
    /// 未知类型
    UNKNOWN,
}
/// 等待插拔事件结果
pub struct WaitResult {
    /// 设备号
    pub dev_name: String,
    /// 事件类型
    pub event: WaitEvent,
    /// 返回结果
    pub result: ErrorDefine,
}
/// 枚举设备结果
pub struct DevEnumResult {
    /// 设备号列表
    pub sz_name_list: Vec<String>,
    /// 返回结果
    pub result: ErrorDefine,
}
/// 连接设备结果
pub struct DevConnectResult {
    /// 设备号
    pub dev_name: String,
    /// 设备连接句柄
    pub h_dev: DEVHANDLE,
    /// 返回结果
    pub result: ErrorDefine,
}
/// 设备状态结果
pub struct DevStateResult {
    /// 设备号
    pub dev_name: String,
    /// 设备状态
    pub state: c_long,
    /// 返回结果
    pub result: ErrorDefine,
}


// 等待设备插拔
const FN_NAME_SKF_WAIT_FOR_DEV_EVENT: &[u8] = b"SKF_WaitForDevEvent";
type SKFWaitForDevEvent = unsafe extern "C" fn(szDevName: LPSTR, puIDevNameLen: ULONGPTR, puIEvent: ULONGPTR) -> c_long;
// 取消等待设备插拔
const FN_NAME_SKF_CANCEL_WAIT_FOR_DEV_EVENT: &[u8] = b"SKF_CancelWaitForDevEvent";
type SKFCancelWaitForDevEvent = unsafe extern "C" fn() -> c_long;
// 枚举设备
const FN_NAME_SKF_ENUMDEV: &[u8] = b"SKF_EnumDev";
type SKFEnumDev = unsafe extern "C" fn(bPresent: c_int, szNameList: LPSTR, puISize: ULONGPTR) -> c_long;
// 获取设备状态
const FN_NAME_SKF_GETDEVSTATE: &[u8] = b"SKF_GetDevState";
type SKFGetDevState = unsafe extern "C" fn(szDevName: SLPSTR, puIDevState: ULONGPTR) -> c_long;
// 连接设备
const FN_NAME_SKF_CONNECTDEV: &[u8] = b"SKF_ConnectDev";
type SKFConnectDev = unsafe extern "C" fn(szName: SLPSTR, phDev: *mut DEVHANDLE) -> c_long;
// 断开连接
const FN_NAME_SKF_DISCONNECTDEV: &[u8] = b"SKF_DisConnectDev";
type SKFDisConnectDev = unsafe extern "C" fn(hDev: DEVHANDLE) -> c_long;

/// 设备管理类
pub struct DeviceManager {
}
impl DeviceManager {
    /// 等待设备插拔
    pub fn wait_dev() -> Option<WaitResult> {
        if let Some(ref fn_wait_dev) = unsafe {LibUtil::load_fun_in_dll::<SKFWaitForDevEvent>(FN_NAME_SKF_WAIT_FOR_DEV_EVENT)} {
            let mut dev_name_vec: Vec<c_char> = vec![0; 255];
            let dev_name: LPSTR = dev_name_vec.as_mut_ptr();
            let mut dev_name_len: c_long = 255;
            let mut event: c_long = 0;
            let result = unsafe{fn_wait_dev(dev_name, &mut dev_name_len, &mut event)};
            let eventen: WaitEvent = if event == 1 { WaitEvent::DEVIN } else if event == 2 { WaitEvent::DEVOUT } else { WaitEvent::UNKNOWN};
            let result: ErrorDefine = ErrorCodes::get_error(result);
            return Some(WaitResult {
                dev_name: if result.is_ok() && eventen != WaitEvent::UNKNOWN { unsafe{jyframe::StringUtil::read_c_strings(dev_name, dev_name_len).join(";")} } else { String::from("") },
                event: eventen,
                result,
            });
        }
        else {
            logger::warn!("load wait device function failed");
        }
        None
    }
    /// 取消等待设备插拔
    pub fn cancel_wait_dev() -> Option<ErrorDefine> {
        if let Some(ref fn_cancel_wait_dev) = unsafe {LibUtil::load_fun_in_dll::<SKFCancelWaitForDevEvent>(FN_NAME_SKF_CANCEL_WAIT_FOR_DEV_EVENT)} {
            let result = unsafe {fn_cancel_wait_dev()};
            return Some(ErrorCodes::get_error(result));
        }
        else {
            logger::warn!("load cancel wait device function failed");
        }
        None
    }
    /// 枚举设备列表
    /// # 参数
    /// - `present` 为true时获取状态可用设备，为false时支持的设备
    pub fn list_dev(present: bool) -> Option<DevEnumResult> {
        if let Some(ref fn_enum_dev) = unsafe {LibUtil::load_fun_in_dll::<SKFEnumDev>(FN_NAME_SKF_ENUMDEV)} {
            let mut sz_name_list_vec: Vec<c_char> = vec![0; 255];
            let sz_name_list: LPSTR = sz_name_list_vec.as_mut_ptr();
            let mut pul_size: c_long = 255;
            let result = unsafe {fn_enum_dev(if present {1} else {0}, sz_name_list, &mut pul_size)};
            return Some(DevEnumResult {
                sz_name_list: if ErrorCodes::is_ok(result) { unsafe {jyframe::StringUtil::read_c_strings(sz_name_list, pul_size)} } else { vec![] },
                result: ErrorCodes::get_error(result),
            });
        }
        else {
            logger::warn!("load list devices function failed");
        }
        None
    }
    /// 连接设备
    /// # 参数
    /// - `dev_name` 设备号
    pub fn connect_dev(dev_name: &str) -> Option<DevConnectResult> {
        if let Some(ref fn_connect_dev) = unsafe {LibUtil::load_fun_in_dll::<SKFConnectDev>(FN_NAME_SKF_CONNECTDEV)} {
            match CString::new(dev_name) {
                Ok(sz_name_cstr) => {
                    let sz_name: SLPSTR = sz_name_cstr.as_ptr();
                    let ph_dev: *mut DEVHANDLE = &mut std::ptr::null_mut();
                    let result = unsafe {fn_connect_dev(sz_name, ph_dev)};
                    return Some(DevConnectResult {
                        dev_name: dev_name.to_string(),
                        h_dev: unsafe {*ph_dev},
                        result: ErrorCodes::get_error(result),
                    });
                },
                Err(err) => {
                    logger::error!("error occured when convert the device name to c-string: {}", err);
                }
            }
        }
        else {
            logger::warn!("load connect device function failed");
        }
        None
    }
    /// 断开连接
    /// # 参数
    /// - `handle` 设备连接句柄
    pub fn disconnect_dev(handle: DEVHANDLE) -> Option<ErrorDefine> {
        if let Some(ref fn_disconnect_dev) = unsafe {LibUtil::load_fun_in_dll::<SKFDisConnectDev>(FN_NAME_SKF_DISCONNECTDEV)} {
            let result = unsafe {fn_disconnect_dev(handle)};
            return Some(ErrorCodes::get_error(result));
        }
        else {
            logger::warn!("load the disconnect device function failed");
        }
        None
    }
    /// 获取设备状态 0不可用；1可用
    /// # 参数
    /// - `dev_name` 设备号
    pub fn get_dev_state(dev_name: &str) -> Option<DevStateResult> {
        if let Some(ref fn_get_dev_state) = unsafe {LibUtil::load_fun_in_dll::<SKFGetDevState>(FN_NAME_SKF_GETDEVSTATE)} {
            match CString::new(dev_name) {
                Ok(sz_dev_name_cstr) => {
                    let sz_dev_name: SLPSTR = sz_dev_name_cstr.as_ptr();
                    let mut state: c_long = -1;
                    let result = unsafe {fn_get_dev_state(sz_dev_name, &mut state)};
                    return Some(DevStateResult { 
                        dev_name: dev_name.to_string(), 
                        state, 
                        result: ErrorCodes::get_error(result),
                    });
                },
                Err(err) => {
                    logger::error!("error occured when convert the device name to c-string: {}", err);
                }
            }
        }
        else {
            logger::warn!("load get device state function failed");
        }
        None
    }
    /// 获取设备连接句柄
    pub fn get_device_available() -> Option<(String, DEVHANDLE)> {
        // 第一步枚举可用设备列表
        if let Some(dev_list) = DeviceManager::list_dev(true) {
            if dev_list.result.is_ok() && dev_list.sz_name_list.len() > 0 {
                // 第二步连接设备
                if let Some(dev_connector) = DeviceManager::connect_dev(&dev_list.sz_name_list[0]) {
                    return if dev_connector.result.is_ok() {Some(((&dev_list.sz_name_list[0]).to_string(), dev_connector.h_dev.clone()))} else {None};
                }
                else {
                    logger::warn!("connect device with name[{}] failed", &dev_list.sz_name_list[0]);
                }
            }
            else {
                logger::warn!("there is no available device to connect");
            }
        }
        else {
            logger::warn!("list devices failed");
        }
        None
    }
}