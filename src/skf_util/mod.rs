use std::io::Write;
use libloading::{Library, Symbol};
use asn1_rs::{FromDer, ToDer};
use log as logger;

#[warn(static_mut_refs)]
pub static mut SKF: Option<Library> = None;
/// dll操作工具类
pub struct LibUtil;
impl LibUtil {
    /// 依赖的dll名称：JKLX_UKEY_GMAPI.dll
    /// 
    /// 位于C:\\Windows\\System32[SysWOW64]下
    pub const LIB_NAME: &str = "JKLX_UKEY_GMAPI.dll";
    pub const LIB_NAME_NEW: &str = "JKLX_LNMRSC_API.dll";
    /// 名称【设备名称、应用名称、窗口名称】长度
    pub const LEN_NAMES: usize = 256;
    /// 密钥长度
    pub const LEN_KEY: usize = 132;
    /// 证书长度
    pub const LEN_CERT: usize = 2048;
    /// 签名长度
    pub const LEN_SIGN: usize = 128;
    /// 加密长度【实际长度是原文长度 + 此值】128 + 32 + 4
    pub const LEN_ENCRY: usize = 164;

    /// 加载dll（全局仅加载一次）
    pub unsafe fn load_lib() {
        if SKF.is_none() {
            SKF = match Library::new(LibUtil::LIB_NAME_NEW) {
                Ok(lib) => Some(lib),
                Err(err) => {
                    logger::error!("error occured when load the library【{}】, try older version: {}", LibUtil::LIB_NAME_NEW, err);
                    match Library::new(LibUtil::LIB_NAME) {
                        Ok(lib) => Some(lib),
                        Err(err) => {
                            logger::error!("error occured when load the library【{}】: {}", LibUtil::LIB_NAME_NEW, err);
                            None
                        },
                    }
                },
            };
        }
        else {
            logger::info!("library has been loaded, no need to reload.");
        }
    }

    /// 获取全局dll加载对象的引用
    pub unsafe fn get_lib() -> Option<&'static Library> {
        return SKF.as_ref();
    }

    /// 从dll中加载function
    /// # 参数
    /// - `func_name` 方法名
    pub unsafe fn load_fun_in_dll<T>(func_name: &[u8]) -> Option<Symbol<T>> 
    where T: 'static 
    {
        LibUtil::load_lib();
        match LibUtil::get_lib() {
            Some(ref lib) => {
                match lib.get::<T>(func_name) {
                    Ok(cfn) => Some(cfn),
                    Err(err) => {
                        logger::error!("error occured when get function【{:?}】: {}", func_name, err);
                        None
                    },
                }
            },
            None => None,
        }
    }
}

enum EnArrType {
    Asn1Sequence,
    Asn1Set,
}
/// asn1工具类
pub struct Asn1Util;
impl Asn1Util {
    /// sm2加密结果转换为asn1编码
    /// # sm2加密的原始结果结构
    /// [0; 32][u8; 32][0; 32][u8; 32][u8; 32][u8; 1][0; 3][u8; n]
    /// # asn1编码结构
    /// ```
    /// Sequence {
    ///     Integer 低32位
    ///     Integer 高32位
    ///     OctetString mac校验
    ///     OctetString 原值密文
    /// }
    /// ```
    pub fn sm2enc_to_asn1(sm2_result: Vec<u8>) -> Option<Vec<u8>> {
        // 最小的sm2原始值长度：64位x，64位y，32位mac位，4位原始值长度表示，其余的是原信息加密值
        if sm2_result.len() < 164 {
            return None;
        }
        let low_bytes = &sm2_result[32..64];
        let high_bytes = &sm2_result[96..128];
        let mac_bytes = &sm2_result[128..160];
        let org_bytes = &sm2_result[164..];
        let mut low_pre: Vec<u8> = vec![];
        let mut high_pre: Vec<u8> = vec![];
        // x和y第一位如果大于等于0x80的需要前置一位0
        if let Some(low_first) = low_bytes.to_vec().first() {
            if *low_first > 127 {
                low_pre.push(0);
            }
        }
        if let Some(high_first) = high_bytes.to_vec().first() {
            if *high_first > 127 {
                high_pre.push(0);
            }
        }
        let mut vector = Vec::new();
        let low_sr = asn1_rs::Integer::new(&[&low_pre[..], low_bytes].concat()[..]).write_der(&mut vector);
        let high_sr = asn1_rs::Integer::new(&[&high_pre[..], high_bytes].concat()[..]).write_der(&mut vector);
        let mac_sr = asn1_rs::OctetString::new(mac_bytes).write_der(&mut vector);
        let org_sr = asn1_rs::OctetString::new(org_bytes).write_der(&mut vector);
        if let (Ok(_), Ok(_), Ok(_), Ok(_)) = (low_sr, high_sr, mac_sr, org_sr) {
            let seq = asn1_rs::Sequence::new(vector.into());
            if let Ok(der_vec) = seq.to_der_vec() {
                return Some(der_vec);
            }
        }
        None
    }
    /// asn1编码转换为sm2加密结果
    pub fn asn1_to_sm2enc(asn1_result: Vec<u8>) -> Option<Vec<u8>> {
        // 兼容一下新点的傻吊写法：Sequence->OctetString[Sequence.encode->x+y+mac+org]，只要里边的Sequence
        let mut real_bytes:Vec<u8> = Vec::new();
        let _ = asn1_rs::Sequence::from_der_and_then(&asn1_result, |bytes| {
            match asn1_rs::OctetString::from_der(bytes) {
                Ok((bytes, oct)) => {
                    real_bytes.extend_from_slice(oct.as_cow());
                    Ok((bytes, (oct)))
                },
                Err(err) => {
                    real_bytes.extend_from_slice(&asn1_result[..]);
                    Err(err)
                },
            }
        });
        let seq_obj = asn1_rs::Sequence::from_der_and_then(&real_bytes, |bytes| {
            return match asn1_rs::Integer::from_der(bytes) {
                Ok((bytes, low_bi)) => {
                    match asn1_rs::Integer::from_der(bytes) {
                        Ok((bytes, high_bi)) => {
                            match asn1_rs::OctetString::from_der(bytes) {
                                Ok((bytes, mac_oc)) => {
                                    match asn1_rs::OctetString::from_der(bytes) {
                                        Ok((bytes, org_oc)) => {
                                            Ok((bytes, (low_bi, high_bi, mac_oc, org_oc)))
                                        },
                                        Err(err) => Err(err),
                                    }
                                },
                                Err(err) => Err(err),
                            }
                        },
                        Err(err) => Err(err),
                    }
                },
                Err(err) => Err(err),
            };
        });
        match seq_obj {
            Ok((_bytes, (low_bi, high_bi, mac_oc, org_oc))) => {
                let low_bytes = low_bi.any().as_bytes().to_vec();
                let high_bytes = high_bi.any().as_bytes().to_vec();
                let mac_bytes = mac_oc.as_cow().to_vec();
                let org_bytes = org_oc.as_cow().to_vec();
                // 低位和高位每个的长度和必须是64
                let low_pre: Vec<u8> = vec![0; 64 - low_bytes.len()];
                let high_pre: Vec<u8> = vec![0; 64 - high_bytes.len()];
                let org_len: Vec<u8> = vec![org_bytes.len() as u8];
                let org_pre: Vec<u8> = vec![0; 3];
    
                return Some([&low_pre[..], &low_bytes[..], &high_pre[..], &high_bytes[..], &mac_bytes[..], &org_len[..], &org_pre[..], &org_bytes[..]].concat());
            },
            Err(err) => {
                logger::error!("error occured when convert the asn1 bytes to sm2 bytes：{}", err);
                return None;
            }
        }
    }
    /// sm2加密结果转换为c1c3c2的标准编码
    pub fn sm2enc_to_c1c3c2(sm2_result: Vec<u8>) -> Option<Vec<u8>> {
        // 最小的sm2原始值长度：64位x，64位y，32位mac位，4位原始值长度表示，其余的是原信息加密值
        if sm2_result.len() >= 164 {
            let low_bytes = &sm2_result[32..64];
            let high_bytes = &sm2_result[96..128];
            let mac_bytes = &sm2_result[128..160];
            let org_bytes = &sm2_result[164..];
            let mut low_pre: Vec<u8> = vec![];
            let mut high_pre: Vec<u8> = vec![];
            // x和y第一位如果大于等于0x80的需要前置一位0
            if let Some(low_first) = low_bytes.to_vec().first() {
                if *low_first > 127 {
                    low_pre.push(0);
                }
            }
            if let Some(high_first) = high_bytes.to_vec().first() {
                if *high_first > 127 {
                    high_pre.push(0);
                }
            }
            let tag_vec: Vec<u8> = vec![0x04];
            return Some([&tag_vec[..], &low_pre[..], low_bytes, &high_pre[..], high_bytes, mac_bytes, org_bytes].concat());
        }
        else {
            logger::error!("the sm2 bytes need to be longer than 164.");
        }
        None
    }
    /// c1c3c2标准编码转换为sm2加密结果
    pub fn c1c3c2_to_sm2enc(c1c3c2_result: Vec<u8>) -> Option<Vec<u8>> {
        // 最小的c1c3c2长度：1位标识位，32位x（也有可能是33），32位y（也有可能是33），32位mac位，其余是原信息加密值
        let mut min_bytes_len = 1 + 32 + 32 + 32;
        if c1c3c2_result.len() >= min_bytes_len {
            let low_pre: Vec<u8> = vec![0; 32];
            let mut low_bytes: Vec<u8> = Vec::new();
            let high_pre: Vec<u8> = vec![0; 32];
            let mut high_bytes: Vec<u8> = Vec::new();
            let mut mac_bytes: Vec<u8> = Vec::new();
            let mut org_len: Vec<u8> = vec![0; 4];
            let mut org_bytes: Vec<u8> = Vec::new();
            let mut start_idx = 1;
            if let Some(low_first) = c1c3c2_result.get(start_idx) {
                if *low_first == 0 {
                    start_idx += 1;
                    min_bytes_len += 1;
                }
            }
            // 最小长度值发生了变化，再判断一次
            if c1c3c2_result.len() < min_bytes_len {
                logger::error!("the c1c3c2 bytes need to be longer than {}.", min_bytes_len);
                return None;
            }
            low_bytes.extend_from_slice(&c1c3c2_result[start_idx..(start_idx + 32)]);
            start_idx += 32;
            if let Some(high_first) = c1c3c2_result.get(start_idx) {
                if *high_first == 0 {
                    start_idx += 1;
                    min_bytes_len += 1;
                }
            }
            // 最小长度值发生了变化，再判断一次
            if c1c3c2_result.len() < min_bytes_len {
                logger::error!("the c1c3c2 bytes need to be longer than {}.", min_bytes_len);
                return None;
            }
            high_bytes.extend_from_slice(&c1c3c2_result[start_idx..(start_idx + 32)]);
            start_idx += 32;
            mac_bytes.extend_from_slice(&c1c3c2_result[start_idx..(start_idx + 32)]);
            start_idx += 32;
            // 剩下的就都是org_bytes了
            org_bytes.extend_from_slice(&c1c3c2_result[start_idx..]);
            if let Some(org_len_first) = org_len.first_mut() {
                *org_len_first = org_bytes.len() as u8;
            }
            return Some([&low_pre[..], &low_bytes[..], &high_pre[..], &high_bytes[..], &mac_bytes[..], &org_len[..], &org_bytes[..]].concat());
        }
        else {
            logger::error!("the c1c3c2 bytes need to be longer than {}.", min_bytes_len);
        }
        None
    }

    /// ecc_sign_to_p7hash内部方法：写入证书颁发机构信息
    fn write_issuer_item(issuer_item: &x509_parser::x509::AttributeTypeAndValue, writer: &mut dyn Write) {
        let mut vec_is_item_wrapper: Vec<u8> = Vec::new();
        let mut vec_is_item_container: Vec<u8> = Vec::new();
        let _ = issuer_item.attr_type().write_der(&mut vec_is_item_container);
        let _ = issuer_item.attr_value().write_der(&mut vec_is_item_container);
        let seq_is_item_container = asn1_rs::Sequence::new(vec_is_item_container.into());
        let _ = seq_is_item_container.write_der(&mut vec_is_item_wrapper);
        let set_is_item_wrapper = asn1_rs::Set::new(vec_is_item_wrapper.into());
        let _ = set_is_item_wrapper.write_der(writer);
    }
    /// ecc签名结果转换为pkcs7-hash-asn1编码
    /// # 参数
    /// - `sign_bytes` 签名值字节数组
    /// - `cert_bytes` 签名证书字节数组
    /// # ecc签名结果结构
    /// [0; 32][u8; 32][0; 32][u8; 32]
    /// # ecc签名的pkcs7编码过于复杂，不做说明
    pub fn ecc_sign_to_p7hash(sign_bytes: Vec<u8>, cert_bytes: Vec<u8>) -> Option<Vec<u8>> {
        // 签名编码容器 
        let mut vec_wrapper: Vec<u8> = Vec::new();
        // 签名编码容器 - OID
        let _ = asn1_rs::oid!(1.2.156.10197.6.1.4.2.2).write_der(&mut vec_wrapper);
        // 签名编码容器 - body 
        // (上下文类型header + sequence)，header依赖于sequence的长度，所以这里的body指的就是sequence，header留在最后定义与写入
        let mut vec_body: Vec<u8> = Vec::new();
        // 签名编码容器 - body - 序号？
        let _ = asn1_rs::Integer::from(1).write_der(&mut vec_body);
        // 签名编码容器 - body - 哈希算法说明
        let mut vec_hash_wrapper: Vec<u8> = Vec::new();
        let mut vec_hash_info: Vec<u8> = Vec::new();
        let _ = asn1_rs::oid!(1.2.156.10197.1.401).write_der(&mut vec_hash_info);
        let _ = asn1_rs::Null::new().write_der(&mut vec_hash_info);
        let seq_hash_info = asn1_rs::Sequence::new(vec_hash_info.into());
        let _ = seq_hash_info.write_der(&mut vec_hash_wrapper);
        let set_hash_wrapper = asn1_rs::Set::new(vec_hash_wrapper.into());
        let _ = set_hash_wrapper.write_der(&mut vec_body);
        // 签名编码容器 - body - 数据类型OID
        let mut vec_data_type: Vec<u8> = Vec::new();
        let _ = asn1_rs::oid!(1.2.156.10197.6.1.4.2.1).write_der(&mut vec_data_type);
        let seq_data_type = asn1_rs::Sequence::new(vec_data_type.into());
        let _ = seq_data_type.write_der(&mut vec_body);
        // 签名编码容器 - body - 签名证书
        // (上下文类型header + sequence)，与body类型，这个header也是依赖于证书内容的长度，所以签名证书指的也是sequence，但好在它只有一个证书对象，所以就直接一起计算写入了
        if let Ok((_bytes, seq_cert_content)) = asn1_rs::Sequence::from_der(&cert_bytes) {
            let cert_len = match seq_cert_content.to_der_len() {
                Ok(len) => len,
                Err(err) => {
                    logger::error!("error occured when calculate the cert content length：{}", err);
                    0
                },
            };
            let _ = asn1_rs::Header::new(asn1_rs::Class::ContextSpecific, true, asn1_rs::Tag(0), asn1_rs::Length::Definite(cert_len)).write_der(&mut vec_body);
            let _ = seq_cert_content.write_der(&mut vec_body);
        }
        // 签名编码容器 - body - 签名信息
        let mut vec_sign_info_wrapper: Vec<u8> = Vec::new();
        let mut vec_sign_info_container: Vec<u8> = Vec::new();
        // 签名编码容器 - body - 签名信息 - 序号？
        let _ = asn1_rs::Integer::from(1).write_der(&mut vec_sign_info_container);
        // 签名编码容器 - body - 签名信息 - 证书颁发单位以及序列号信息
        if let Ok((_bytes, cert)) = x509_parser::prelude::X509Certificate::from_der(&cert_bytes) {
            let mut vec_issuer_wrapper: Vec<u8> = Vec::new();
            let mut vec_issuer_container: Vec<u8> = Vec::new();
            for issuer_it in cert.issuer().iter() {
                if let Some(issuer_item) = issuer_it.iter().last() {
                    Asn1Util::write_issuer_item(issuer_item, &mut vec_issuer_container);
                }
            }
            // if let Some(issuer_c) = cert.issuer().iter_country().last() {
            //     Asn1Util::write_issuer_item(issuer_c, &mut vec_issuer_container);
            // }
            // if let Some(issuer_o) = cert.issuer().iter_organization().last() {
            //     Asn1Util::write_issuer_item(issuer_o, &mut vec_issuer_container);
            // }
            // if let Some(issuer_cn) = cert.issuer().iter_common_name().last() {
            //     Asn1Util::write_issuer_item(issuer_cn, &mut vec_issuer_container);
            // }
            let seq_issuer_container = asn1_rs::Sequence::new(vec_issuer_container.into());
            let _ = seq_issuer_container.write_der(&mut vec_issuer_wrapper);
            let _ = asn1_rs::Integer::new(cert.raw_serial()).write_der(&mut vec_issuer_wrapper);
            let seq_issuer_info_wrapper = asn1_rs::Sequence::new(vec_issuer_wrapper.into());
            let _ = seq_issuer_info_wrapper.write_der(&mut vec_sign_info_container);
        }
        // 签名编码容器 - body - 签名信息 - 签名哈希算法
        let mut vec_sign_hash: Vec<u8> = Vec::new();
        let _ = asn1_rs::oid!(1.2.156.10197.1.401).write_der(&mut vec_sign_hash);
        let _ = asn1_rs::Null::new().write_der(&mut vec_sign_hash);
        let seq_sign_hash = asn1_rs::Sequence::new(vec_sign_hash.into());
        let _ = seq_sign_hash.write_der(&mut vec_sign_info_container);
        // 签名编码容器 - body - 签名信息 - 签名算法（加密算法）
        let mut vec_sign_encry: Vec<u8> = Vec::new();
        let _ = asn1_rs::oid!(1.2.156.10197.1.301.1).write_der(&mut vec_sign_encry);
        let _ = asn1_rs::Null::new().write_der(&mut vec_sign_encry);
        let seq_sign_encry = asn1_rs::Sequence::new(vec_sign_encry.into());
        let _ = seq_sign_encry.write_der(&mut vec_sign_info_container);
        // 签名编码容器 - body - 签名信息 - 签名值
        let r_bytes = &sign_bytes[32..64];
        let s_bytes = &sign_bytes[96..128];
        let mut r_pre: Vec<u8> = Vec::new();
        let mut s_pre: Vec<u8> = Vec::new();
        if let Some(r_first) = r_bytes.to_vec().first() {
            if *r_first > 127 {
                r_pre.push(0);
            }
        }
        if let Some(s_first) = s_bytes.to_vec().first() {
            if *s_first > 127 {
                s_pre.push(0);
            }
        }
        let mut vec_signature: Vec<u8> = Vec::new();
        let _ = asn1_rs::Integer::new(&[&r_pre[..], r_bytes].concat()[..]).write_der(&mut vec_signature);
        let _ = asn1_rs::Integer::new(&[&s_pre[..], s_bytes].concat()[..]).write_der(&mut vec_signature);
        let seq_signature = asn1_rs::Sequence::new(vec_signature.into());
        match seq_signature.to_der_vec() {
            Ok(sign_asn1_bytes) => {
                let oct_signature = asn1_rs::OctetString::new(&sign_asn1_bytes);
                let _ = oct_signature.write_der(&mut vec_sign_info_container);
            },
            Err(err) => {
                logger::error!("error occured when convert the signature：{}", err);
            }
        }
        // 签名编码容器 - body - 签名信息【写入】
        let seq_sign_info_container = asn1_rs::Sequence::new(vec_sign_info_container.into());
        let _ = seq_sign_info_container.write_der(&mut vec_sign_info_wrapper);
        let set_sign_info_wrapper = asn1_rs::Set::new(vec_sign_info_wrapper.into());
        let _ = set_sign_info_wrapper.write_der(&mut vec_body);
        // 最后形成bodySequence并计算长度定入到签名编码容器中
        let seq_body = asn1_rs::Sequence::new(vec_body.into());
        // 签名编码容器 - body-header + body 写入（因为header里的长度依赖于body，所以最后写入）
        let body_len = match seq_body.to_der_len() {
            Ok(len) => len,
            Err(err) => {
                logger::error!("error occured when calculate the body length：{}", err);
                0
            },
        };
        let _ = asn1_rs::Header::new(asn1_rs::Class::ContextSpecific, true, asn1_rs::Tag(0), asn1_rs::Length::Definite(body_len)).write_der(&mut vec_wrapper);
        let _ = seq_body.write_der(&mut vec_wrapper);
        let seq_wrapper = asn1_rs::Sequence::new(vec_wrapper.into());
        match seq_wrapper.to_der_vec() {
            Ok(seq_encode) => Some(seq_encode.clone()),
            Err(err) => {
                logger::error!("error occured when convert the p7hashed asn1 signature：{}", err);
                None
            }
        }
    }
    /// p7hash_to_ecc_sign内部方法：循环数组内容，取其最后一个元素的bytes
    fn read_last_item_in_arr(mut content_bytes: Vec<u8>) -> Option<Vec<u8>> {
        loop {
            if let Ok((bytes, any_type)) = asn1_rs::Any::from_der(&content_bytes) {
                // 读到最后一个元素时剩余bytes长度为0
                if bytes.len() == 0 {
                    match any_type.to_der_vec() {
                        Ok(bytes_vec) => {
                            return Some(bytes_vec.clone());
                        }
                        Err(err) => {
                            logger::error!("error occured when convert the asn1 item：{}", err);
                            break;
                        }
                    };
                }
                else {
                    content_bytes = bytes.to_vec();
                    continue;
                }
            }
            else {
                break;
            }
        }
        None
    }
    /// p7hash_to_ecc_sign内部方法：从一个Sequence或Set序列中读取最后一个元素bytes数组
    fn read_last_item_in_sequence(sequence_bytes: Vec<u8>, arr_type: EnArrType) -> Option<Vec<u8>> {
        match arr_type {
            EnArrType::Asn1Sequence => {
                match asn1_rs::Sequence::from_der_and_then(&sequence_bytes, |bytes| {
                    match Asn1Util::read_last_item_in_arr(bytes.to_vec()) {
                        Some(last_bytes) => Ok((bytes, last_bytes.clone())),
                        None => Err(asn1_rs::Err::Error(asn1_rs::Error::Unsupported)),
                    }
                }) {
                    Ok((_bytes, last_bytes)) => {
                        return Some(last_bytes.clone());
                    },
                    Err(err) => {
                        logger::error!("error occured when read the last item in sequence：{}", err);
                        return None;
                    },
                }
            },
            EnArrType::Asn1Set => {
                match asn1_rs::Set::from_der_and_then(&sequence_bytes, |bytes| {
                    match Asn1Util::read_last_item_in_arr(bytes.to_vec()) {
                        Some(last_bytes) => Ok((bytes, last_bytes)),
                        None => Err(asn1_rs::Err::Error(asn1_rs::Error::Unsupported)),
                    }
                }) {
                    Ok((_bytes, last_bytes)) => {
                        return Some(last_bytes.clone());
                    },
                    Err(err) => {
                        logger::error!("error occured when read the last item in set：{}", err);
                        return None;
                    },
                }
            },
        }
    }
    /// pkcs7-asn1编码转换为ecc签名结果
    pub fn p7hash_to_ecc_sign(p7bytes: Vec<u8>) -> Option<Vec<u8>> {
        // 读第一层的ctx_header元素
        if let Some(last_bytes) = Asn1Util::read_last_item_in_sequence(p7bytes.clone(), EnArrType::Asn1Sequence) {
            // ctx_header下的sequence元素
            match asn1_rs::Header::from_der(&last_bytes) {
                Ok((last_bytes, _header)) => {
                    // 读sequence下的最后一个元素（里边有签名信息）,是一个set元素
                    if let Some(last_bytes) = Asn1Util::read_last_item_in_sequence(last_bytes.to_vec(), EnArrType::Asn1Sequence) {
                        // 读取set下的签名信息容器，是一个sequence
                        if let Some(last_bytes) = Asn1Util::read_last_item_in_sequence(last_bytes.clone(), EnArrType::Asn1Set) {
                            // 读sequence下的签名值，是一个octetstring
                            if let Some(last_bytes) = Asn1Util::read_last_item_in_sequence(last_bytes.clone(), EnArrType::Asn1Sequence) {
                                // 读octetstring里的byte数组内容
                                match asn1_rs::OctetString::from_der(&last_bytes) {
                                    Ok((_last_bytes, sign_oct)) => {
                                        // 解析最终的签名sequence序列，并返回其中的r和s
                                        match asn1_rs::Sequence::from_der_and_then(&sign_oct.as_cow().to_vec(), |bytes| {
                                            match asn1_rs::Integer::from_der(bytes) {
                                                Ok((bytes, r_bi)) => {
                                                    match asn1_rs::Integer::from_der(bytes) {
                                                        Ok((bytes, s_bi)) => Ok((bytes, (r_bi, s_bi))),
                                                        Err(err) => Err(err),
                                                    }
                                                },
                                                Err(err) => Err(err),
                                            }
                                        }) {
                                            Ok((_bytes, (r_bi, s_bi))) => {
                                                let r_bytes = r_bi.any().as_bytes().to_vec();
                                                let s_bytes = s_bi.any().as_bytes().to_vec();
                                                // 低位和高位分别是两个长度64的byte数组
                                                let r_pre: Vec<u8> = vec![0; 64 - r_bytes.len()];
                                                let s_pre: Vec<u8> = vec![0; 64 - s_bytes.len()];
                                                return Some([&r_pre[..], &r_bytes[..], &s_pre[..], &s_bytes[..]].concat());
                                            },
                                            Err(err) => {
                                                logger::error!("error occured when read final signature bytes: {}", err);
                                            }
                                        }
                                    },
                                    Err(err) => {
                                        logger::error!("p7hashed signature with wrong asn1 struct：{}", err);
                                    }
                                }
                            }
                        }
                    }
                },
                Err(err) => {
                    logger::error!("p7hashed signature with wrong asn1 struct：{}", err);
                }
            }
        }
        None
    }
}
