use std::{ffi::CString, os::raw::{c_char, c_int, c_long}};
use base64::Engine;
use super::*;

/// 枚举容器列表结果
pub struct EnumContainerResult {
    /// 容器名称列表
    pub sz_container_list: Vec<String>,
    /// 返回结果
    pub result: ErrorDefine,
}
/// 容器打开结果
pub struct ContainerOpenResult {
    /// 容器名称
    pub sz_container_name: String,
    /// 容器打开句柄
    pub h_container: CONTAINERHANDLE,
    /// 返回结果
    pub result: ErrorDefine,
}
/// 容器类型
pub enum ContainerType {
    /// 未知类型
    CTUnknown,
    /// `1` RSA类型
    CTRsa,
    /// `2` SM2类型
    CTSm2,
}
/// 获取容器类型结果
pub struct ContainerTypeResult {
    /// 容器类型
    pub container_type: ContainerType,
    /// 返回结果
    pub result: ErrorDefine,
}
/// 证书导出结果
pub struct ExCertResult {
    /// 证书字节数组
    pub cert: Vec<u8>,
    /// 证书base64
    pub cert64: String,
    /// 返回结果
    pub result: ErrorDefine,
}

// 枚举应用内的容器
const FN_NAME_SKF_ENUMCONTAINER: &[u8] = b"SKF_EnumContainer";
type SKFEnumContainer = unsafe extern "C" fn(hApplication: APPLICATIONHANDLE, szContainerName: LPSTR, pulSize: ULONGPTR) -> c_long;
// 打开容器
const FN_NAME_SKF_OPENCONTAINER: &[u8] = b"SKF_OpenContainer";
type SKFOpenContainer = unsafe extern "C" fn(hApplication: APPLICATIONHANDLE, szContainerName: SLPSTR, phContainer: *mut CONTAINERHANDLE) -> c_long;
// 关闭容器
const FN_NAME_SKF_CLOSECONTAINER: &[u8] = b"SKF_CloseContainer";
type SKFCloseContainer = unsafe extern "C" fn(hContainer: CONTAINERHANDLE) -> c_long;
// 获取容器类型
const FN_NAME_SKF_GETCONTAINERTYPE: &[u8] = b"SKF_GetContainerType";
type SKFGetContainerType = unsafe extern "C" fn(hContainer: CONTAINERHANDLE, pulContainerType: ULONGPTR) -> c_long;
// 导出证书
const FN_NAME_SKF_EXPORTCERTIFICATE: &[u8] = b"SKF_ExportCertificate";
type SKFExportCertificate = unsafe extern "C" fn(hContainer: CONTAINERHANDLE, bSignFlag: c_int, pbCert: BYTEPTR, pulCertLen: ULONGPTR) -> c_long;

/// 容器管理类
pub struct ContainerManager;
impl ContainerManager {
    /// 枚举应用内的容器
    /// # 参数
    /// - `h_app` 应用打开句柄
    pub fn list_containers(h_app: APPLICATIONHANDLE) -> Option<EnumContainerResult> {
        if let Some(ref fn_enum_container) = unsafe {LibUtil::load_fun_in_dll::<SKFEnumContainer>(FN_NAME_SKF_ENUMCONTAINER)} {
            let mut sz_container_name_vec: Vec<c_char> = vec![0; 255];
            let sz_container_name: LPSTR = sz_container_name_vec.as_mut_ptr();
            let mut pul_size: c_long = 255;
            let result = unsafe {fn_enum_container(h_app, sz_container_name, &mut pul_size)};
            return Some(EnumContainerResult {
                sz_container_list: if ErrorCodes::is_ok(result) { unsafe {jyframe::StringUtil::read_c_strings(sz_container_name, pul_size)} } else { vec![] },
                result: ErrorCodes::get_error(result),
            });
        }
        None
    }
    /// 打开容器
    /// # 参数
    /// - `h_app` 应用打开句柄
    /// - `container_name` 容器名称
    pub fn open_container(h_app: APPLICATIONHANDLE, container_name: &str) -> Option<ContainerOpenResult> {
        if let Some(ref fn_open_container) = unsafe {LibUtil::load_fun_in_dll::<SKFOpenContainer>(FN_NAME_SKF_OPENCONTAINER)} {
            if let Ok(sz_container_name_cstr) = CString::new(container_name) {
                let sz_container_name: SLPSTR = sz_container_name_cstr.as_ptr();
                let ph_container: *mut CONTAINERHANDLE = &mut std::ptr::null_mut();
                let result = unsafe {fn_open_container(h_app, sz_container_name, ph_container)};
                return Some(ContainerOpenResult {
                    sz_container_name: container_name.to_string(),
                    h_container: unsafe {*ph_container},
                    result: ErrorCodes::get_error(result),
                });
            }
        }
        None
    }
    /// 关闭容器
    /// # 参数
    /// - `h_container` 容器打开句柄
    pub fn close_container(h_container: CONTAINERHANDLE) -> Option<ErrorDefine> {
        if let Some(ref fn_close_container) = unsafe {LibUtil::load_fun_in_dll::<SKFCloseContainer>(FN_NAME_SKF_CLOSECONTAINER)} {
            let result = unsafe {fn_close_container(h_container)};
            return Some(ErrorCodes::get_error(result));
        }
        None
    }
    /// 获取容器类型
    /// # 参数
    /// - `h_container` 容器打开句柄
    pub fn get_container_type(h_container: CONTAINERHANDLE) -> Option<ContainerTypeResult> {
        if let Some(ref fn_get_ct_type) = unsafe {LibUtil::load_fun_in_dll::<SKFGetContainerType>(FN_NAME_SKF_GETCONTAINERTYPE)} {
            let mut pul_container_type: c_long = 0;
            let result = unsafe {fn_get_ct_type(h_container, &mut pul_container_type)};
            return Some(ContainerTypeResult {
                container_type: if pul_container_type == 1 {ContainerType::CTRsa} else if pul_container_type == 2 {ContainerType::CTSm2} else {ContainerType::CTUnknown},
                result: ErrorCodes::get_error(result),
            });
        }
        None
    }
    /// 导出容器内的证书
    /// # 参数
    /// - `h_container` 容器打开句柄
    /// - `b_sign_flag` 是否导出签名证书，为true时导出签名证书，否则导出加密证书
    pub fn export_cert(h_container: CONTAINERHANDLE, b_sign_flag: bool) -> Option<ExCertResult> {
        if let Some(ref fn_export_cert) = unsafe {LibUtil::load_fun_in_dll::<SKFExportCertificate>(FN_NAME_SKF_EXPORTCERTIFICATE)} {
            let mut cert: Vec<u8> = vec![0; 2048];
            let mut cert_len: c_long = 2048;
            let result = unsafe {fn_export_cert(h_container, if b_sign_flag {1} else {0}, cert.as_mut_ptr(), &mut cert_len)};
            if ErrorCodes::is_ok(result) && cert_len > 0 {
                cert.truncate(cert_len as usize);
            }
            let mut rtn: ExCertResult = ExCertResult {
                cert: cert.clone(),
                cert64: String::from(""),
                result: ErrorCodes::get_error(result),
            };
            rtn.cert64 = base64::engine::general_purpose::STANDARD.encode(&rtn.cert);
            return Some(rtn);
        }
        None
    }
    /// 获取可用容器句柄
    /// # 参数
    /// - `h_app` 应用句柄
    pub fn get_container_available(h_app: APPLICATIONHANDLE) -> Option<(String, CONTAINERHANDLE)> {
        // 第一步枚举容器
        if let Some(container_list) = ContainerManager::list_containers(h_app.clone()) {
            if container_list.result.is_ok() && container_list.sz_container_list.len() > 0 {
                // 第六步打开容器
                if let Some(container_opener) = ContainerManager::open_container(h_app.clone(), &container_list.sz_container_list[0]) {
                    return if container_opener.result.is_ok() {Some(((&container_list.sz_container_list[0]).to_string(), container_opener.h_container.clone()))} else {None};
                }
            }
        }
        None
    }
}