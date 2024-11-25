use std::os::raw::{c_char, c_long};
use log as logger;
use super::*;

/// 枚举文件列表结果
pub struct FileEnumResult {
    /// 文件名称列表
    pub sz_file_list: Vec<String>,
    /// 返回结果
    pub result: ErrorDefine,
}

// 枚举应用内的文件列表
const FN_NAME_SKF_ENUMFILES: &[u8] = b"SKF_EnumFiles";
type SKFEnumFiles = unsafe extern "C" fn(hApplication: APPLICATIONHANDLE, szFileList: LPSTR, pulSize: ULONGPTR) -> c_long;

/// 文件管理类
pub struct FileManager;
impl FileManager {
    /// 枚举应用内的文件列表
    /// # 参数
    /// - `h_app` 应用打开句柄
    pub fn list_files(h_app: APPLICATIONHANDLE) -> Option<FileEnumResult> {
        if let Some(ref fn_enum_files) = unsafe {LibUtil::load_fun_in_dll::<SKFEnumFiles>(FN_NAME_SKF_ENUMFILES)} {
            let mut sz_file_list_vec: Vec<c_char> = vec![0; 255];
            let sz_file_list: LPSTR = sz_file_list_vec.as_mut_ptr();
            let mut pul_size: c_long = 255;
            let result = unsafe {fn_enum_files(h_app, sz_file_list, &mut pul_size)};
            return Some(FileEnumResult {
                sz_file_list: if ErrorCodes::is_ok(result) { unsafe {jyframe::StringUtil::read_c_strings(sz_file_list, pul_size)} } else { vec![] },
                result: ErrorCodes::get_error(result),
            });
        }
        else {
            logger::warn!("load list files function failed");
        }
        None
    }
}