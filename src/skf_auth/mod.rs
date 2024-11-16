use std::{ffi::CString, os::raw::c_long};
use super::*;

/// pin码校验结果
pub struct CheckPinResult {
    /// 尝试次数
    pub retry_count: c_long,
    /// 返回结果
    pub result: ErrorDefine,
}

// pin校验
const FN_NAME_SKF_VERIFYPIN: &[u8] = b"SKF_VerifyPIN";
type SKFVerifyPIN = unsafe extern "C" fn(hApplication: APPLICATIONHANDLE, ulPINType: c_long, szPIN: SLPSTR, pulRetryCount: ULONGPTR) -> c_long;

/// 认证管理类
pub struct AuthManager;
impl AuthManager {
    /// pin校验（pin类型：0管理员；1用户。这里只用用户类型）
    /// # 参数
    /// - `h_app` 应用打开句柄
    /// - `pin` pin值
    pub fn check_pin(h_app: APPLICATIONHANDLE, pin: &str) -> Option<CheckPinResult> {
        if let Some(ref fn_check_pin) = unsafe {LibUtil::load_fun_in_dll::<SKFVerifyPIN>(FN_NAME_SKF_VERIFYPIN)} {
            if let Ok(pin_cstr) = CString::new(pin) {
                let sz_pin: SLPSTR = pin_cstr.as_ptr();
                let mut retry_count: c_long = 0;
                let result = unsafe {fn_check_pin(h_app, 1 as c_long, sz_pin, &mut retry_count)};
                return Some(CheckPinResult {
                    retry_count,
                    result: ErrorCodes::get_error(result),
                });
            }
        }
        None
    }
}