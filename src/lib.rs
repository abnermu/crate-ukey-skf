use log as logger;

mod skf_types;
mod skf_error;
mod skf_util;
mod skf_device;
mod skf_auth;
mod skf_application;
mod skf_file;
mod skf_container;
mod skf_alogrithm;

use asn1_rs::FromDer;
use base64::Engine;
pub use skf_types::*;
pub use skf_error::*;
pub use skf_util::*;
pub use skf_device::*;
pub use skf_auth::*;
pub use skf_application::*;
pub use skf_file::*;
pub use skf_container::*;
pub use skf_alogrithm::*;

#[allow(dead_code)]
struct PinStore {
    dev_name: String,
    pin: String,
}
static mut PIN_STORE: Option<PinStore> = None;
/// 容器信息存储
#[derive(Debug)]
struct ContainerInfo {
    container_name: String,
    h_container: Option<CONTAINERHANDLE>,
}
/// 应用信息存储
#[derive(Debug)]
struct AppInfo {
    app_name: String,
    h_app: Option<APPLICATIONHANDLE>,
    containers: Vec<ContainerInfo>,
}
/// 设备信息存储
#[derive(Debug)]
struct DeviceInfo {
    dev_name: String,
    h_dev: Option<DEVHANDLE>,
    applications: Vec<AppInfo>,
}
/// 设备数据
#[allow(dead_code)]
#[derive(Debug)]
struct DeviceData {
    dev_name: String,
    h_dev: DEVHANDLE,
    app_name: String,
    h_app: APPLICATIONHANDLE,
    constainer_name: String,
    h_container: CONTAINERHANDLE,
}
/// 证书信息类型
#[derive(PartialEq)]
pub enum CertInfo {
    /// 完整证书内容
    CertContent,
    /// 证书序列号
    SerialNumber,
    /// 有效期开始时间
    ValidFrom,
    /// 有效期截止时间
    ValidTo,
    /// 使用者密钥标识符
    SubjectKeyIdentifier,
    /// 使用者姓名
    CommonName,
    /// 颁发机构
    Issuer,
}
/// 初始化设备---获取设备、应用、容器句柄
fn init_device() -> Option<DeviceData> {
    let mut dev_info: DeviceInfo = DeviceInfo {
        dev_name: String::from(""),
        h_dev: None,
        applications: Vec::new(),
    };
    // 设备只取第一个，把该设备下所有可用的应用、容器统统取出来，后续再判断有效性
    if let Some(dev_list_rst) = DeviceManager::list_dev(true) {
        if dev_list_rst.result.is_ok() && dev_list_rst.sz_name_list.len() > 0 {
            if let Some(dev_conn_rst) = DeviceManager::connect_dev(dev_list_rst.sz_name_list[0].as_str()) {
                if dev_conn_rst.result.is_ok() {
                    dev_info.dev_name = dev_conn_rst.dev_name.clone();
                    dev_info.h_dev = Some(dev_conn_rst.h_dev.clone());
                    if let Some(app_list_rst) = AppManager::list_apps(dev_conn_rst.h_dev.clone()) {
                        if app_list_rst.result.is_ok() && app_list_rst.sz_app_name.len() > 0 {
                            for app_name in app_list_rst.sz_app_name {
                                if let Some(app_open_rst) = AppManager::open_app(dev_conn_rst.h_dev.clone(), app_name.as_str()) {
                                    if app_open_rst.result.is_ok() {
                                        let mut app_info: AppInfo = AppInfo {
                                            app_name: app_open_rst.sz_app_name.clone(),
                                            h_app: Some(app_open_rst.h_app.clone()),
                                            containers: Vec::new(),
                                        };
                                        if let Some(ct_list_rst) = ContainerManager::list_containers(app_open_rst.h_app.clone()) {
                                            if ct_list_rst.result.is_ok() && ct_list_rst.sz_container_list.len() > 0 {
                                                for ct_name in ct_list_rst.sz_container_list {
                                                    if let Some(ct_open_rst) = ContainerManager::open_container(app_open_rst.h_app.clone(), ct_name.as_str()) {
                                                        let ct_info: ContainerInfo = ContainerInfo {
                                                            container_name: ct_open_rst.sz_container_name.clone(),
                                                            h_container: Some(ct_open_rst.h_container.clone()),
                                                        };
                                                        app_info.containers.push(ct_info);
                                                    }
                                                }
                                            }
                                        }
                                        dev_info.applications.push(app_info);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    // 存在设备句柄、应用以及容器才做后续处理，否则认为初始化失败
    if dev_info.h_dev.is_some() && dev_info.applications.len() > 0 && dev_info.applications[0].containers.len() > 0 {
        logger::info!("设备共包含{}个应用", dev_info.applications.len());
        for i in (0..dev_info.applications.len()).rev() {
            logger::info!("应用({})内共包含{}个容器", i + 1, dev_info.applications[i].containers.len());
            for j in (0..dev_info.applications[i].containers.len()).rev() {
                // 证书无效的容器直接关闭删除，判断过程中出现异常情况的也都删除
                if let Some(cert_rst) = ContainerManager::export_cert(dev_info.applications[i].containers[j].h_container.unwrap().clone(), true) {
                    if cert_rst.result.is_ok() {
                        if let Ok((_bytes, cert)) = x509_parser::prelude::X509Certificate::from_der(&cert_rst.cert.clone()) {
                            if cert.validity().not_after.timestamp() < chrono::Local::now().timestamp() {
                                logger::warn!("应用({})->容器({})证书过期，已删除", i + 1, j + 1);
                                let rm_ct = dev_info.applications[i].containers.remove(j);
                                let _ = ContainerManager::close_container(rm_ct.h_container.unwrap().clone());
                                continue;
                            }
                        }
                        else {
                            logger::warn!("应用({})->容器({})证书转换失败，已删除", i + 1, j + 1);
                            let rm_ct = dev_info.applications[i].containers.remove(j);
                            let _ = ContainerManager::close_container(rm_ct.h_container.unwrap().clone());
                            continue;
                        }
                    }
                    else {
                        logger::warn!("应用({})->容器({})导出证书失败，已删除", i + 1, j + 1);
                        let rm_ct = dev_info.applications[i].containers.remove(j);
                        let _ = ContainerManager::close_container(rm_ct.h_container.unwrap().clone());
                        continue;
                    }
                }
                else {
                    logger::warn!("应用({})->容器({})导出证书失败，已删除", i + 1, j + 1);
                    let rm_ct = dev_info.applications[i].containers.remove(j);
                    let _ = ContainerManager::close_container(rm_ct.h_container.unwrap().clone());
                    continue;
                }
            }
            // 没有容器的应用直接关闭删除
            if dev_info.applications[i].containers.len() <= 0 {
                logger::warn!("应用({})不包含有效容器，已删除", i + 1);
                let rm_app = dev_info.applications.remove(i);
                let _ = AppManager::close_app(rm_app.h_app.unwrap().clone());
                continue;
            }
        }
        // 如果还存在有效应用、容器的取第一个应用以及第一个容器出来，其他的都不要了，关闭删除
        if dev_info.applications.len() > 0 && dev_info.applications[0].containers.len() > 0 {
            let dev_data: DeviceData = DeviceData {
                dev_name: dev_info.dev_name.clone(),
                h_dev: dev_info.h_dev.unwrap().clone(),
                app_name: dev_info.applications[0].app_name.clone(),
                h_app: dev_info.applications[0].h_app.unwrap().clone(),
                constainer_name: dev_info.applications[0].containers[0].container_name.clone(),
                h_container: dev_info.applications[0].containers[0].h_container.unwrap().clone(),
            };
            for i in (1..dev_info.applications.len()).rev() {
                for j in (1..dev_info.applications[i].containers.len()).rev() {
                    let rm_ct = dev_info.applications[i].containers.remove(j);
                    let _ = ContainerManager::close_container(rm_ct.h_container.unwrap().clone());
                    continue;
                }
                let rm_app = dev_info.applications.remove(i);
                let _ = AppManager::close_app(rm_app.h_app.unwrap().clone());
                continue;
            }
            return Some(dev_data);
        }
    }
    logger::error!("设备初始化失败");
    None
}
/// 获取证书内容
/// #参数
/// - `for_sign` 获取签名证书
fn get_cert_content(for_sign: bool) -> Option<Vec<u8>> {
    if let Some(dev_data) = init_device() {
        // 最后导出证书
        if let Some(cert) = ContainerManager::export_cert(dev_data.h_container.clone(), for_sign) {
            // 马上要返回了，后边所有代码都不会执行了，所以得把设备句柄、应用句柄、容器句柄都关一遍
            ContainerManager::close_container(dev_data.h_container.clone());
            AppManager::close_app(dev_data.h_app.clone());
            DeviceManager::disconnect_dev(dev_data.h_dev.clone());
            return if cert.result.is_ok() {Some(cert.cert.clone())} else {None};
        }
        // 最后关闭容器
        ContainerManager::close_container(dev_data.h_container.clone());
        // 最后关闭应用
        AppManager::close_app(dev_data.h_app.clone());
        // 最后关闭连接
        DeviceManager::disconnect_dev(dev_data.h_dev.clone());
    }
    None
}
/// 获取证书序列号
pub fn get_cert_serial_number(cert_bytes: &[u8]) -> Option<String> {
    if let Ok((_bytes, cert)) = x509_parser::prelude::X509Certificate::from_der(&cert_bytes) {
        return Some(jyframe::StringUtil::bytes_to_hex(cert.raw_serial()));
    }
    None
}
/// 获取证书有效期开始时间
/// 格式化：yyyy/MM/dd HH:mm:ss
pub fn get_cert_valid_from(cert_bytes: &[u8]) -> Option<String> {
    if let Ok((_bytes, cert)) = x509_parser::prelude::X509Certificate::from_der(&cert_bytes) {
        if let Some(valid_from) = chrono::DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0) {
            return Some(valid_from.format("%Y/%m/%d %H:%M:%S").to_string());
        }
    }
    None
}
/// 获取证书有效期截止时间
/// 格式化：yyyy/MM/dd HH:mm:ss
pub fn get_cert_valid_to(cert_bytes: &[u8]) -> Option<String> {
    if let Ok((_bytes, cert)) = x509_parser::prelude::X509Certificate::from_der(&cert_bytes) {
        if let Some(valid_from) = chrono::DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0) {
            return Some(valid_from.format("%Y/%m/%d %H:%M:%S").to_string());
        }
    }
    None
}
/// 获取证书使用者密钥标识符---SubjectKeyIdentifier
/// - `oid` 2.5.29.14
pub fn get_cert_subject_key_id(cert_bytes: &[u8]) -> Option<String> {
    if let Ok((_bytes, cert)) = x509_parser::prelude::X509Certificate::from_der(&cert_bytes) {
        if let Ok(Some(subject_key_id)) = cert.get_extension_unique(&asn1_rs::oid!(2.5.29.14)) {
            if let Ok((_bytes, asn1_subject_key_id)) = asn1_rs::Any::from_der(subject_key_id.value) {
                return Some(jyframe::StringUtil::bytes_to_hex(asn1_subject_key_id.data))
            }
        }
    }
    None
}
/// 获取证书使用者名称
/// 先取extension中oid为1.2.86.1的值，如果没有的话从subject中取common name并以@作为分割取第二个值
pub fn get_cert_common_name(cert_bytes: &[u8]) -> Option<String> {
    if let Ok((_bytes, cert)) = x509_parser::prelude::X509Certificate::from_der(&cert_bytes) {
        if let Ok(Some(cn)) = cert.get_extension_unique(&asn1_rs::oid!(1.2.86.1)) {
            if let Ok((_bytes, asn1_cn)) = asn1_rs::Any::from_der(cn.value) {
                if let Ok(cn_str) = String::from_utf8(asn1_cn.data.to_vec()) {
                    return Some(cn_str);
                }
            }
        }
        if let Some(common_name) =  cert.subject().iter_common_name().last() {
            if let Ok(cn_str) = common_name.as_str() {
                if cn_str.contains('@') {
                    let cn_arr: Vec<&str> = cn_str.split('@').collect();
                    return Some(cn_arr[1].to_string());
                }
                else {
                    return Some(cn_str.to_string());
                }
            }
        }
    }
    None
}
/// 获取证书颁发机构
pub fn get_cert_issuer(cert_bytes: &[u8]) -> Option<String> {
    if let Ok((_bytes, cert)) = x509_parser::prelude::X509Certificate::from_der(&cert_bytes) {
        return Some(cert.issuer().to_string());
    }
    None
}
///判断当前设备是否校验过
pub fn is_pin_checked(sz_name: &str) -> bool {
    return unsafe {PIN_STORE.is_some() && PIN_STORE.as_ref().unwrap().dev_name == sz_name};
}
/// pin码校验
/// # 参数
/// - `pin` 用户密码
pub fn check_pin(pin: &str) -> Option<CheckPinResult> {
    if let Some(dev_data) = init_device() {
        if let Some(check_result) = AuthManager::check_pin(dev_data.h_app.clone(), pin) {
            // 马上要返回了，后边所有代码都不会执行了，所以得把设备句柄、应用句柄都关一遍
            ContainerManager::close_container(dev_data.h_container.clone());
            AppManager::close_app(dev_data.h_app.clone());
            DeviceManager::disconnect_dev(dev_data.h_dev.clone());
            unsafe {
                PIN_STORE = Some(PinStore {
                    dev_name: dev_data.dev_name.clone(),
                    pin: pin.to_string(),
                });
            };
            return Some(check_result);
        }
        // 最后关闭容器
        ContainerManager::close_container(dev_data.h_container.clone());
        // 最后关闭应用
        AppManager::close_app(dev_data.h_app.clone());
        // 最后关闭连接
        DeviceManager::disconnect_dev(dev_data.h_dev.clone());
    }
    None
}
/// 获取设备号
/// # 返回值
/// 返回第一个可用状态的设备号
pub fn get_device_num() -> String {
    if let Some(list_result) = DeviceManager::list_dev(true) {
        if list_result.result.is_ok() && list_result.sz_name_list.len() > 0 {
            return String::from(list_result.sz_name_list.get(0).unwrap());
        }
    }
    String::from("")
}
/// 获取CA信息
/// # 参数
/// - `for_sign` 获取签名证书信息
pub fn get_ca_info(info_type: CertInfo, for_sign: bool) -> String {
    if let Some(cert_bytes) = get_cert_content(for_sign) {
        if info_type == CertInfo::CertContent {
            return base64::engine::general_purpose::STANDARD.encode(&cert_bytes);
        }
        else if info_type == CertInfo::SerialNumber {
            if let Some(serial_number) = get_cert_serial_number(&cert_bytes) {
                return serial_number;
            }
        }
        else if info_type == CertInfo::ValidFrom {
            if let Some(valid_from) = get_cert_valid_from(&cert_bytes) {
                return valid_from;
            }
        }
        else if info_type == CertInfo::ValidTo {
            if let Some(valid_to) = get_cert_valid_to(&cert_bytes) {
                return valid_to;
            }
        }
        else if info_type == CertInfo::SubjectKeyIdentifier {
            if let Some(key_identifier) = get_cert_subject_key_id(&cert_bytes) {
                return key_identifier;
            }
        }
        else if info_type == CertInfo::CommonName {
            if let Some(cn) = get_cert_common_name(&cert_bytes) {
                return cn;
            }
        }
        else if info_type == CertInfo::Issuer {
            if let Some(issuer) = get_cert_issuer(&cert_bytes) {
                return issuer;
            }
        }
    }
    String::from("")
}
/// 公钥加密，加密结果为asn1编码形式
/// # 参数
/// - `data` 原文
pub fn encrypt(data: &str) -> String {
    if let Some(dev_data) = init_device() {
        // 加密需要传参公钥，所以得导出一下公钥
        if let Some(pub_key) = SecretService::ex_public_key(dev_data.h_container.clone(), false) {
            if pub_key.result.is_ok() {
                if let Some(encrypted) = SecretService::ecc_encrypt(dev_data.h_dev.clone(), pub_key.key.clone(), data) {
                    // 马上要返回了，后边所有代码都不会执行了，所以得把设备句柄、应用句柄、容器句柄都关一遍
                    ContainerManager::close_container(dev_data.h_container.clone());
                    AppManager::close_app(dev_data.h_app.clone());
                    DeviceManager::disconnect_dev(dev_data.h_dev.clone());
                    return if encrypted.result.is_ok() {encrypted.encrypted_asn1} else {String::from("")};
                }
            }
        }
        // 最后关闭容器
        ContainerManager::close_container(dev_data.h_container.clone());
        // 最后关闭应用
        AppManager::close_app(dev_data.h_app.clone());
        // 最后关闭连接
        DeviceManager::disconnect_dev(dev_data.h_dev.clone());
    }
    String::from("")
}
/// 私钥解密
/// # 参数
/// - `data` 原文
pub fn decrypt(data: &str) -> String {
    if let Some(dev_data) = init_device() {
        // 解密前需要校验用户口令
        if is_pin_checked(&dev_data.dev_name) || AuthManager::check_pin_dialog() {
            if let Some(decrypted) = SecretService::ecc_decrypt(dev_data.h_container.clone(), data) {
                // 马上要返回了，后边所有代码都不会执行了，所以得把设备句柄、应用句柄、容器句柄都关一遍
                ContainerManager::close_container(dev_data.h_container.clone());
                AppManager::close_app(dev_data.h_app.clone());
                DeviceManager::disconnect_dev(dev_data.h_dev.clone());
                return if decrypted.result.is_ok() {decrypted.decryptedplain} else {String::from("")};
            }
        }
        // 最后关闭容器
        ContainerManager::close_container(dev_data.h_container.clone());
        // 最后关闭应用
        AppManager::close_app(dev_data.h_app.clone());
        // 最后关闭连接
        DeviceManager::disconnect_dev(dev_data.h_dev.clone());
    }
    String::from("")
}
/// 私钥签名，签名结果为pkcs7 hash-asn1编码形式
/// # 参数
/// - `data` 原文
pub fn sign_data(data: &str) -> String {
    if let Some(dev_data) = init_device() {
        if let Some(sign_cert) = ContainerManager::export_cert(dev_data.h_container.clone(), true) {
            if sign_cert.result.is_ok() {
                // 签名前需要校验用户口令
                if is_pin_checked(&dev_data.dev_name) || AuthManager::check_pin_dialog() {
                    if let Some(signed) = SecretService::ecc_sign_data(dev_data.h_container.clone(), data, &sign_cert.cert64) {
                        // 马上要返回了，后边所有代码都不会执行了，所以得把设备句柄、应用句柄、容器句柄都关一遍
                        ContainerManager::close_container(dev_data.h_container.clone());
                        AppManager::close_app(dev_data.h_app.clone());
                        DeviceManager::disconnect_dev(dev_data.h_dev.clone());
                        return if signed.result.is_ok() {signed.signature_asn1} else {String::from("")};
                    }
                }
            }
        }
        // 最后关闭容器
        ContainerManager::close_container(dev_data.h_container.clone());
        // 最后关闭应用
        AppManager::close_app(dev_data.h_app.clone());
        // 最后关闭连接
        DeviceManager::disconnect_dev(dev_data.h_dev.clone());
    }
    String::from("")
}
/// 验签
/// # 参数
/// - `org` 原文
/// - `signature` 签名值
pub fn verify_sign(org: &str, signature: &str) -> bool {
    if let Some(dev_data) = init_device() {
        // 验签需要传参公钥，所以得导出一下公钥
        if let Some(pub_key) = SecretService::ex_public_key(dev_data.h_container.clone(), true) {
            if pub_key.result.is_ok() {
                if let Some(verified) = SecretService::ecc_verify(dev_data.h_dev.clone(), org, signature, pub_key.key.clone()) {
                    // 马上要返回了，后边所有代码都不会执行了，所以得把设备句柄、应用句柄、容器句柄都关一遍
                    ContainerManager::close_container(dev_data.h_container.clone());
                    AppManager::close_app(dev_data.h_app.clone());
                    DeviceManager::disconnect_dev(dev_data.h_dev.clone());
                    return verified.is_ok();
                }
            }
        }
        // 最后关闭容器
        ContainerManager::close_container(dev_data.h_container.clone());
        // 最后关闭应用
        AppManager::close_app(dev_data.h_app.clone());
        // 最后关闭连接
        DeviceManager::disconnect_dev(dev_data.h_dev.clone());
    }
    false
}