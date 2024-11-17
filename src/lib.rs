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
/// 获取证书内容
/// #参数
/// - `for_sign` 获取签名证书
fn get_cert_content(for_sign: bool) -> Option<Vec<u8>> {
    // 第一步获取可用设备句柄
    if let Some(h_dev) = DeviceManager::get_device_available() {
        // 第二步获取应用句柄
        if let Some(h_app) = AppManager::get_app_available(h_dev.clone()) {
            // 第三步获取容器句柄
            if let Some(h_container) = ContainerManager::get_container_available(h_app.clone()) {
                // 最后导出证书
                if let Some(cert) = ContainerManager::export_cert(h_container.clone(), for_sign) {
                    // 马上要返回了，后边所有代码都不会执行了，所以得把设备句柄、应用句柄、容器句柄都关一遍
                    ContainerManager::close_container(h_container);
                    AppManager::close_app(h_app);
                    DeviceManager::disconnect_dev(h_dev);
                    return if cert.result.is_ok() {Some(cert.cert.clone())} else {None};
                }
                // 使用完之后关闭容器
                ContainerManager::close_container(h_container);
            }
            // 使用完之后关闭应用
            AppManager::close_app(h_app);
        }
        // 使用完之后关闭设备连接
        DeviceManager::disconnect_dev(h_dev);
    }
    None
}
/// 获取证书序列号
fn get_cert_serial_number(cert_bytes: &[u8]) -> Option<String> {
    if let Ok((_bytes, cert)) = x509_parser::prelude::X509Certificate::from_der(&cert_bytes) {
        return Some(StringUtil::read_to_hex(cert.raw_serial()));
    }
    None
}
/// 获取证书有效期开始时间
/// 格式化：yyyy/MM/dd HH:mm:ss
fn get_cert_valid_from(cert_bytes: &[u8]) -> Option<String> {
    if let Ok((_bytes, cert)) = x509_parser::prelude::X509Certificate::from_der(&cert_bytes) {
        if let Some(valid_from) = chrono::DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0) {
            return Some(valid_from.format("%Y/%m/%d %H:%M:%S").to_string());
        }
    }
    None
}
/// 获取证书有效期截止时间
/// 格式化：yyyy/MM/dd HH:mm:ss
fn get_cert_valid_to(cert_bytes: &[u8]) -> Option<String> {
    if let Ok((_bytes, cert)) = x509_parser::prelude::X509Certificate::from_der(&cert_bytes) {
        if let Some(valid_from) = chrono::DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0) {
            return Some(valid_from.format("%Y/%m/%d %H:%M:%S").to_string());
        }
    }
    None
}
/// 获取证书使用者密钥标识符---SubjectKeyIdentifier
/// - `oid` 2.5.29.14
fn get_cert_subject_key_id(cert_bytes: &[u8]) -> Option<String> {
    if let Ok((_bytes, cert)) = x509_parser::prelude::X509Certificate::from_der(&cert_bytes) {
        if let Ok(Some(subject_key_id)) = cert.get_extension_unique(&asn1_rs::oid!(2.5.29.14)) {
            if let Ok((_bytes, asn1_subject_key_id)) = asn1_rs::Any::from_der(subject_key_id.value) {
                return Some(StringUtil::read_to_hex(asn1_subject_key_id.data))
            }
        }
    }
    None
}
/// 获取证书使用者名称
/// 先取extension中oid为1.2.86.1的值，如果没有的话从subject中取common name并以@作为分割取第二个值
fn get_cert_common_name(cert_bytes: &[u8]) -> Option<String> {
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
fn get_cert_issuer(cert_bytes: &[u8]) -> Option<String> {
    if let Ok((_bytes, cert)) = x509_parser::prelude::X509Certificate::from_der(&cert_bytes) {
        return Some(cert.issuer().to_string());
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
    // 第一步获取可用设备句柄
    if let Some(h_dev) = DeviceManager::get_device_available() {
        // 第二步获取应用句柄
        if let Some(h_app) = AppManager::get_app_available(h_dev.clone()) {
            // 第三步获取容器句柄
            if let Some(h_container) = ContainerManager::get_container_available(h_app.clone()) {
                // 加密需要传参公钥，所以得导出一下公钥
                if let Some(pub_key) = SecretService::ex_public_key(h_container.clone(), false) {
                    if pub_key.result.is_ok() {
                        if let Some(encrypted) = SecretService::ecc_encrypt(h_dev.clone(), pub_key.key.clone(), data) {
                            // 马上要返回了，后边所有代码都不会执行了，所以得把设备句柄、应用句柄、容器句柄都关一遍
                            ContainerManager::close_container(h_container);
                            AppManager::close_app(h_app);
                            DeviceManager::disconnect_dev(h_dev);
                            return if encrypted.result.is_ok() {encrypted.encrypted_asn1} else {String::from("")};
                        }
                    }
                }
                // 最后关闭容器
                ContainerManager::close_container(h_container);
            }
            // 最后关闭应用
            AppManager::close_app(h_app);
        }
        // 最后关闭连接
        DeviceManager::disconnect_dev(h_dev);
    }
    String::from("")
}
/// 私钥解密
/// # 参数
/// - `data` 原文
pub fn decrypt(data: &str) -> String {
    // 第一步获取可用设备句柄
    if let Some(h_dev) = DeviceManager::get_device_available() {
        // 第二步获取应用句柄
        if let Some(h_app) = AppManager::get_app_available(h_dev.clone()) {
            // 第三步获取容器句柄
            if let Some(h_container) = ContainerManager::get_container_available(h_app.clone()) {
                if let Some(decrypted) = SecretService::ecc_decrypt(h_container.clone(), data) {
                    // 马上要返回了，后边所有代码都不会执行了，所以得把设备句柄、应用句柄、容器句柄都关一遍
                    ContainerManager::close_container(h_container);
                    AppManager::close_app(h_app);
                    DeviceManager::disconnect_dev(h_dev);
                    return if decrypted.result.is_ok() {decrypted.decryptedplain} else {String::from("")};
                }
                // 最后关闭容器
                ContainerManager::close_container(h_container);
            }
            // 最后关闭应用
            AppManager::close_app(h_app);
        }
        // 最后关闭连接
        DeviceManager::disconnect_dev(h_dev);
    }
    String::from("")
}
/// 私钥签名，签名结果为pkcs7 hash-asn1编码形式
/// # 参数
/// - `data` 原文
pub fn sign_data(data: &str) -> String {
    // 第一步获取可用设备句柄
    if let Some(h_dev) = DeviceManager::get_device_available() {
        // 第二步获取应用句柄
        if let Some(h_app) = AppManager::get_app_available(h_dev.clone()) {
            // 第三步获取容器句柄
            if let Some(h_container) = ContainerManager::get_container_available(h_app.clone()) {
                if let Some(sign_cert) = ContainerManager::export_cert(h_container.clone(), true) {
                    if sign_cert.result.is_ok() {
                        if let Some(signed) = SecretService::ecc_sign_data(h_container.clone(), data, &sign_cert.cert64) {
                            // 马上要返回了，后边所有代码都不会执行了，所以得把设备句柄、应用句柄、容器句柄都关一遍
                            ContainerManager::close_container(h_container);
                            AppManager::close_app(h_app);
                            DeviceManager::disconnect_dev(h_dev);
                            return if signed.result.is_ok() {signed.signature_asn1} else {String::from("")};
                        }
                    }
                }
                // 最后关闭容器
                ContainerManager::close_container(h_container);
            }
            // 最后关闭应用
            AppManager::close_app(h_app);
        }
        // 最后关闭连接
        DeviceManager::disconnect_dev(h_dev);
    }
    String::from("")
}
/// 验签
/// # 参数
/// - `org` 原文
/// - `signature` 签名值
pub fn verify_sign(org: &str, signature: &str) -> bool {
    // 第一步获取可用设备句柄
    if let Some(h_dev) = DeviceManager::get_device_available() {
        // 第二步获取应用句柄
        if let Some(h_app) = AppManager::get_app_available(h_dev.clone()) {
            // 第三步获取容器句柄
            if let Some(h_container) = ContainerManager::get_container_available(h_app.clone()) {
                // 验签需要传参公钥，所以得导出一下公钥
                if let Some(pub_key) = SecretService::ex_public_key(h_container.clone(), true) {
                    if pub_key.result.is_ok() {
                        if let Some(verified) = SecretService::ecc_verify(h_dev.clone(), org, signature, pub_key.key.clone()) {
                            // 马上要返回了，后边所有代码都不会执行了，所以得把设备句柄、应用句柄、容器句柄都关一遍
                            ContainerManager::close_container(h_container);
                            AppManager::close_app(h_app);
                            DeviceManager::disconnect_dev(h_dev);
                            return verified.is_ok();
                        }
                    }
                }
                // 最后关闭容器
                ContainerManager::close_container(h_container);
            }
            // 最后关闭应用
            AppManager::close_app(h_app);
        }
        // 最后关闭连接
        DeviceManager::disconnect_dev(h_dev);
    }
    false
}