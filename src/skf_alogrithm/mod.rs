use std::os::raw::{c_int, c_long};
use base64::Engine;
use log as logger;
use super::*;

/// 生成随机数结果
pub struct RandomGenResult {
    /// 随机数字节数组
    pub random_bytes: Vec<u8>,
    /// 返回结果
    pub result: ErrorDefine,
}
/// 公钥导出结果
pub struct PubKeyExResult {
    /// 公钥字节数组
    pub key: Vec<u8>,
    /// 公钥base64
    pub key64: String,
    /// 返回结果
    pub result: ErrorDefine,
}
/// ECC签名结果
pub struct ECCSignResult {
    /// 签名值字节数组
    pub signature: Vec<u8>,
    /// 签名base64
    pub signature64: String,
    /// 签名的pkcs7-asn1结构base64
    pub signature_asn1: String,
    /// 返回结果
    pub result: ErrorDefine,
}
/// ECC加密结果
pub struct ECCEncryptResult {
    /// 加密原值
    pub data: String,
    /// 加密结果字节数组
    pub encrypted: Vec<u8>,
    /// 加密结果base64
    pub encrypted64: String,
    /// 加密结果的标准c1c3c2表示
    pub encrypted_c1c3c2: String,
    /// 加密结果的asn1表示
    pub encrypted_asn1: String,
    /// 返回结果
    pub result: ErrorDefine,
}
/// ECC解密结果
pub struct ECCDecryptResult {
    /// 解密前的值
    pub data: String,
    /// 解密结果字节数组
    pub decrypted: Vec<u8>,
    /// 解密结果的普通文本表示
    pub decryptedplain: String,
    /// 返回结果
    pub result: ErrorDefine,
}

// 生成随机数
const FN_NAME_SKF_GENRANDOM: &[u8] = b"SKF_GenRandom";
type SKFGenRandom = unsafe extern "C" fn(hDev: DEVHANDLE, pbRandom: BYTEPTR, ulRandomLen: c_long) -> c_long;
// 导出公钥
const FN_NAME_SKF_EXPORTPUBLICKEY: &[u8] = b"SKF_ExportPublicKey";
type SKFExportPublicKey = unsafe extern "C" fn(hContainer: CONTAINERHANDLE, bSignFlag: c_int, pbBlob: BYTEPTR, pulBlobLen: ULONGPTR) -> c_long;
// ECC签名
const FN_NAME_SKF_ECCSIGNDATA: &[u8] = b"SKF_ECCSignData";
type SKFECCSignData = unsafe extern "C" fn(hContainer: CONTAINERHANDLE, pbData: SBYTEPTR, ulDataLen: c_long, pSignature: BYTEPTR) -> c_long;
// ECC验签
const FN_NAME_SKF_ECCVERIFY: &[u8] = b"SKF_ECCVerify";
type SKFECCVerify = unsafe extern "C" fn(hDev: DEVHANDLE, pECCPubKeyBlob: SBYTEPTR, pbData: SBYTEPTR, ulDataLen: c_long, pSignature: SBYTEPTR) -> c_long;
// ECC加密
const FN_NAME_SKF_EXTECCENCRYPT: &[u8] = b"SKF_ExtECCEncrypt";
type SKFExtECCEncrypt = unsafe extern "C" fn(hDev: DEVHANDLE, pECCPubKeyBlob: SBYTEPTR, pbPlainText: SBYTEPTR, ulPlainTextLen: c_long, pCipherText: BYTEPTR) -> c_long;
// ECC解密
const FN_NAME_SKFEX_ECCDECRYPT: &[u8] = b"SKFEX_ECCDecrypt";
type SKFEXECCDecrypt = unsafe extern "C" fn(hContainer: CONTAINERHANDLE, ulKeySpec: c_long, pCipherText: SBYTEPTR, pbData: BYTEPTR, pdwDataLen: ULONGPTR) -> c_long;

/// 密码服务类
pub struct SecretService;
impl SecretService {
    /// 生成随机数
    /// # 参数
    /// - `h_dev` 设备连接句柄
    /// - `random_len` 随机数长度
    pub fn get_random(h_dev: DEVHANDLE, random_len: usize) -> Option<RandomGenResult> {
        if let Some(ref fn_get_random) = unsafe {LibUtil::load_fun_in_dll::<SKFGenRandom>(FN_NAME_SKF_GENRANDOM)} {
            let mut random_bytes: Vec<u8> = vec![0; random_len];
            let result = unsafe {fn_get_random(h_dev, random_bytes.as_mut_ptr(), random_len as c_long)};
            return Some(RandomGenResult {
                random_bytes: random_bytes.clone(),
                result: ErrorCodes::get_error(result),
            });
        }
        else {
            logger::warn!("load get random function failed");
        }
        None
    }
    /// 导出公钥
    /// # 参数
    /// - `h_container` 容器打开句柄
    /// - `b_sign_flag` 是否导出签名公钥，为true时导出签名公钥，否则导出加密公钥
    pub fn ex_public_key(h_container: CONTAINERHANDLE, b_sign_flag: bool) -> Option<PubKeyExResult> {
        if let Some(ref fn_ex_pubkey) = unsafe {LibUtil::load_fun_in_dll::<SKFExportPublicKey>(FN_NAME_SKF_EXPORTPUBLICKEY)} {
            let mut key_blob: Vec<u8> = vec![0; 132];
            let mut key_len: c_long = 132;
            let result = unsafe {fn_ex_pubkey(h_container, if b_sign_flag {1} else {0}, key_blob.as_mut_ptr(), &mut key_len)};
            if ErrorCodes::is_ok(result) && key_len > 0 {
                key_blob.truncate(key_len as usize);
            }
            else {
                logger::error!("export public key failed");
            }
            let mut rtn = PubKeyExResult {
                key: key_blob.clone(),
                key64: String::from(""),
                result: ErrorCodes::get_error(result),
            };
            rtn.key64 = base64::engine::general_purpose::STANDARD.encode(&rtn.key);
            return Some(rtn);
        }
        else {
            logger::warn!("load export public key function failed");
        }
        None
    }
    /// ECC签名，直接操作byte数组
    /// # 参数
    /// - `h_container` 容器打开句柄
    /// - `data_bytes` 原文byte数组
    /// - `cert_bytes` 签名证书byte数组
    pub fn ecc_sign_bytes(h_container: CONTAINERHANDLE, data_bytes: Vec<u8>, cert_bytes: Vec<u8>) -> Option<ECCSignResult> {
        if let Some(ref fn_ecc_sign) = unsafe {LibUtil::load_fun_in_dll::<SKFECCSignData>(FN_NAME_SKF_ECCSIGNDATA)} {
            let mut signature: Vec<u8> = vec![0; 128];
            let result = unsafe {fn_ecc_sign(h_container, data_bytes.as_ptr(), data_bytes.len() as c_long, signature.as_mut_ptr())};
            let mut rtn = ECCSignResult {
                signature: signature.clone(),
                signature64: String::from(""),
                signature_asn1: String::from(""),
                result: ErrorCodes::get_error(result),
            };
            rtn.signature64 = base64::engine::general_purpose::STANDARD.encode(&rtn.signature);
            rtn.signature_asn1 = if let Some(asn1_bytes) = Asn1Util::ecc_sign_to_p7hash(rtn.signature.clone(), cert_bytes) {
                base64::engine::general_purpose::STANDARD.encode(&asn1_bytes)
            }
            else {
                String::from("")
            };
            return Some(rtn);
        }
        else {
            logger::warn!("load ecc sign function failed");
        }
        None
    }
    /// ECC签名，仅处理base64字符串
    /// # 参数
    /// - `h_container` 容器打开句柄
    /// - `data` 原文base64
    /// - `cert` 证书base64
    pub fn ecc_sign_data(h_container: CONTAINERHANDLE, data: &str, cert: &str) -> Option<ECCSignResult> {
        match base64::engine::general_purpose::STANDARD.decode(data) {
            Ok(data_bytes) => {
                match base64::engine::general_purpose::STANDARD.decode(cert) {
                    Ok(cert_bytes) => {
                        return SecretService::ecc_sign_bytes(h_container, data_bytes, cert_bytes);
                    },
                    Err(err) => {
                        logger::error!("error occured when ecc sign to convert the cert from base64 to bytes: {}", err);
                    }
                }
            },
            Err(err) => {
                logger::error!("error occured when ecc sign to convert the data from base64 to bytes: {}", err);
            }
        }
        None
    }
    /// ECC验签，直接操作byte数组
    /// # 参数
    /// - `h_dev` 设备打开句柄
    /// - `data_bytes` 原文byte数组
    /// - `sign_bytes` 签名值byte数组
    /// - `pubkey` 公钥byte数组
    pub fn ecc_verify_bytes(h_dev: DEVHANDLE, data_bytes: Vec<u8>, sign_bytes: Vec<u8>, pubkey: Vec<u8>) -> Option<ErrorDefine> {
        if let Some(ref fn_verify) = unsafe {LibUtil::load_fun_in_dll::<SKFECCVerify>(FN_NAME_SKF_ECCVERIFY)} {
            let result = unsafe {fn_verify(h_dev, pubkey.as_ptr(), data_bytes.as_ptr(), data_bytes.len() as c_long, sign_bytes.as_ptr())};
            return Some(ErrorCodes::get_error(result));
        }
        else {
            logger::warn!("load ecc verify function failed");
        }
        None
    }
    /// ECC验签，仅处理base64字符串【pkcs7-hash asn1编码的】
    /// # 参数
    /// - `h_dev` 设备打开句柄
    /// - `data` 原文base64
    /// - `signature` 签名值base64
    /// - `pubkey` 公钥byte数组
    pub fn ecc_verify(h_dev: DEVHANDLE, data: &str, signature: &str, pubkey: Vec<u8>) -> Option<ErrorDefine> {
        match base64::engine::general_purpose::STANDARD.decode(data) {
            Ok(data_bytes) => {
                match base64::engine::general_purpose::STANDARD.decode(signature) {
                    Ok(sign_bytes) => {
                        if let Some(sign_bytes_primitive) = Asn1Util::p7hash_to_ecc_sign(sign_bytes.clone()) {
                            return SecretService::ecc_verify_bytes(h_dev, data_bytes, sign_bytes_primitive, pubkey);
                        }
                        else {
                            logger::error!("convert p7hashed signature to primitive bytes failed");
                        }
                    },
                    Err(err) => {
                        logger::error!("error occured when ecc verify and convert the signature from base64 to bytes: {}", err);
                    }
                }
            },
            Err(err) => {
                logger::error!("error occured when ecc verify and convert the data from base64 to bytes: {}", err);
            }
        }
        None
    }
    /// ECC加密，最大原文长度160个字节
    /// # 参数
    /// - `h_dev` 设备连接句柄
    /// - `pub_key` 公钥byte数组
    /// - `data` 原文base64
    pub fn ecc_encrypt(h_dev: DEVHANDLE, pub_key: Vec<u8>, data: &str) -> Option<ECCEncryptResult> {
        if let Some(ref fn_encry) = unsafe {LibUtil::load_fun_in_dll::<SKFExtECCEncrypt>(FN_NAME_SKF_EXTECCENCRYPT)} {
            let data_vec: Vec<u8> = data.as_bytes().to_vec();
            let mut encrypted: Vec<u8> = vec![0; 128 + 32 + 4 + data_vec.len()];
            let result = unsafe {fn_encry(h_dev, pub_key.as_ptr(), data_vec.as_ptr(), data_vec.len() as c_long, encrypted.as_mut_ptr())};
            let mut rtn = ECCEncryptResult { 
                data: data.to_string(), 
                encrypted: encrypted.clone(), 
                encrypted64: String::from(""),
                encrypted_c1c3c2: String::from(""),
                encrypted_asn1: String::from(""),
                result: ErrorCodes::get_error(result) ,
            };
            rtn.encrypted64 = base64::engine::general_purpose::STANDARD.encode(&rtn.encrypted);
            rtn.encrypted_c1c3c2 = if let Some(c1c3c2_val) = Asn1Util::sm2enc_to_c1c3c2(rtn.encrypted.clone()) {
                base64::engine::general_purpose::STANDARD.encode(c1c3c2_val.clone())
            }
            else {
                String::from("")
            };
            rtn.encrypted_asn1 = if let Some(asn1_val) = Asn1Util::sm2enc_to_asn1(rtn.encrypted.clone()) {
                base64::engine::general_purpose::STANDARD.encode(asn1_val.clone())
            } 
            else {
                String::from("")
            };
            return Some(rtn);
        }
        else {
            logger::warn!("load ecc encrypt function failed");
        }
        None
    }
    /// ECC解密（直接操作byte数组）
    /// # 参数
    /// - `h_container` 容器打开句柄
    /// - `data` 加密值byte数组
    pub fn ecc_decrypt_bytes(h_container: CONTAINERHANDLE, data: Vec<u8>) -> Option<ECCDecryptResult> {
        if let Some(ref fn_decry) = unsafe {LibUtil::load_fun_in_dll::<SKFEXECCDecrypt>(FN_NAME_SKFEX_ECCDECRYPT)} {
            let mut decrypted: Vec<u8> = vec![0; data.len()];
            let mut dec_len: c_long = data.len() as c_long;
            let result = unsafe {fn_decry(h_container, 1 as c_long, data.as_ptr(), decrypted.as_mut_ptr(), &mut dec_len)};
            if ErrorCodes::is_ok(result) && dec_len > 0 {
                decrypted.truncate(dec_len as usize);
            }
            else {
                logger::error!("ecc decrypt failed");
            }
            return Some(ECCDecryptResult {
                data: base64::engine::general_purpose::STANDARD.encode(&data),
                decrypted: decrypted.clone(),
                decryptedplain: if let Ok(dec_plain) = String::from_utf8(decrypted.clone()) {dec_plain} else {String::from("")},
                result: ErrorCodes::get_error(result),
            });
        }
        else {
            logger::warn!("load ecc decrypt function failed");
        }
        None
    }
    /// ECC解密（密文是base64字符串）
    /// # 参数
    /// - `h_container` 容器打开句柄
    /// - `data` 加密值base64
    pub fn ecc_decrypt_primitive(h_container: CONTAINERHANDLE, data: &str) -> Option<ECCDecryptResult> {
        match base64::engine::general_purpose::STANDARD.decode(data) {
            Ok(bytes) => {
                return SecretService::ecc_decrypt_bytes(h_container, bytes.clone());
            },
            Err(err) => {
                logger::error!("error occured when decode the data from base64 to bytes: {}", err);
            }
        }
        None
    }
    /// ECC解密（密文是标准c1c3c2的base64字符）
    /// # 参数
    /// - `h_container` 容器打开句柄
    /// - `data` 加密值base64
    pub fn ecc_decrypt_c1c3c2(h_container: CONTAINERHANDLE, data: &str) -> Option<ECCDecryptResult> {
        match base64::engine::general_purpose::STANDARD.decode(data) {
            Ok(c1c3c2_bytes) => {
                if let Some(bytes) = Asn1Util::c1c3c2_to_sm2enc(c1c3c2_bytes) {
                    return SecretService::ecc_decrypt_bytes(h_container, bytes.clone());
                }
                else {
                    logger::warn!("convert c1c3c2 style encrypted data to bytes failed");
                }
            },
            Err(err) => {
                logger::error!("error occured when convert the data from base64 to bytes: {}", err);
            }
        }
        None
    }
    /// ECC解密（密文是asn1编码的base64字符串）
    /// # 参数
    /// - `h_container` 容器打开句柄
    /// - `data` 加密值base64
    pub fn ecc_decrypt_asn1(h_container: CONTAINERHANDLE, data: &str) -> Option<ECCDecryptResult> {
        match base64::engine::general_purpose::STANDARD.decode(data) {
            Ok(asn1_bytes) => {
                if let Some(bytes) = Asn1Util::asn1_to_sm2enc(asn1_bytes.clone()) {
                    return SecretService::ecc_decrypt_bytes(h_container, bytes.clone());
                }
                else {
                    logger::warn!("convert asn1 style encrypted data to bytes failed");
                }
            },
            Err(err) => {
                logger::error!("error occured when convert the data from base64 to bytes: {}", err);
            }
        }
        None
    }
    /// ECC解密（不考虑密文组成形式，只管是base64） 
    /// # 参数
    /// - `h_container` 容器打开句柄
    /// - `data` 加密值base64
    pub fn ecc_decrypt(h_container: CONTAINERHANDLE, data: &str) -> Option<ECCDecryptResult> {
        // 先用asn1，再用c1c3c2，最后再考虑原始值的形式
        if let Some(dec_asn1) = SecretService::ecc_decrypt_asn1(h_container, data) {
            if dec_asn1.result.is_ok() {
                return Some(dec_asn1);
            }
        }
        else {
            logger::info!("try to do asn1 style decrypt failed, will try c1c3c2 next");
        }
        if let Some(dec_c1c3c2) = SecretService::ecc_decrypt_c1c3c2(h_container, data) {
            if dec_c1c3c2.result.is_ok() {
                return Some(dec_c1c3c2);
            }
        }
        else {
            logger::info!("try to do c1c3c2 style decrypt failed, will try primitive next");
        }
        if let Some(dec_primitive) = SecretService::ecc_decrypt_primitive(h_container, data) {
            return Some(dec_primitive);
        }
        else {
            logger::info!("try to do primitive style decrypt failed");
        }
        None
    }
}