use std::os::raw::c_long;

/// 错误定义
pub struct ErrorDefine {
    /// 错误编码
    pub code: c_long,
    /// 错误描述文本
    pub msg: &'static str,
}
impl ErrorDefine {
    /// 判断错误类型是否为OK
    pub fn is_ok(&self) -> bool {
        return self.code == 0x00000000;
    }
}
/// 错误编码集合
pub struct ErrorCodes;
impl ErrorCodes {
    pub const SAR_OK:                        ErrorDefine = ErrorDefine {code: 0x00000000, msg: "成功"};
    pub const SAR_FAIL:                      ErrorDefine = ErrorDefine {code: 0x0A000001, msg: "失败"};
    pub const SAR_UNKNOWN_ERR:               ErrorDefine = ErrorDefine {code: 0x0A000002, msg: "未知异常"}; 
    pub const SAR_NOT_SUPPORT_YET_ERR:       ErrorDefine = ErrorDefine {code: 0x0A000003, msg: "尚不支持"}; 
    pub const SAR_FILE_ERR:                  ErrorDefine = ErrorDefine {code: 0x0A000004, msg: "文件操作错误"}; 
    pub const SAR_INVALID_HANDLE_ERR:        ErrorDefine = ErrorDefine {code: 0x0A000005, msg: "无效句柄" }; 
    pub const SAR_INVALID_PARAM1_ERR:         ErrorDefine = ErrorDefine {code: 0x0A000006, msg: "无效参数"}; 
    pub const SAR_INVALID_PARAM2_ERR:         ErrorDefine = ErrorDefine {code: 0x0A00BBBB, msg: "无效参数"}; 
    pub const SAR_READ_FILE_ERR:             ErrorDefine = ErrorDefine {code: 0x0A000007, msg: "读文件错误"}; 
    pub const SAR_WRITE_FILE_ERR:            ErrorDefine = ErrorDefine {code: 0x0A000008, msg: "写文件错误"}; 
    pub const SAR_NAME_LEN_ERR:              ErrorDefine = ErrorDefine {code: 0x0A000009, msg: "名称长度错误"}; 
    pub const SAR_KEY_USAGE_ERR:             ErrorDefine = ErrorDefine {code: 0x0A00000A, msg: "密钥用途错误"}; 
    pub const SAR_MODULES_LEN_ERR:           ErrorDefine = ErrorDefine {code: 0x0A00000B, msg: "模块长度错误"}; 
    pub const SAR_NOT_INITIALIZE_ERR:        ErrorDefine = ErrorDefine {code: 0x0A00000C, msg: "未初始化"}; 
    pub const SAR_OBJ_ERR:                   ErrorDefine = ErrorDefine {code: 0x0A00000D, msg: "对象错误"}; 
    pub const SAR_MEMORY_ERR:                ErrorDefine = ErrorDefine {code: 0x0A00000E, msg: "内存错误"}; 
    pub const SAR_TIMEOUT_ERR:               ErrorDefine = ErrorDefine {code: 0x0A00000F, msg: "超时"}; 
    pub const SAR_IN_DATALEN_ERR:            ErrorDefine = ErrorDefine {code: 0x0A000010, msg: "输入数据长度错误"}; 
    pub const SAR_IN_DATA_ERR:               ErrorDefine = ErrorDefine {code: 0x0A000011, msg: "输入数据错误"}; 
    pub const SAR_GEN_RAND_ERR:              ErrorDefine = ErrorDefine {code: 0x0A000012, msg: "生成随机数错误"}; 
    pub const SAR_HASH_OBJ_ERR:              ErrorDefine = ErrorDefine {code: 0x0A000013, msg: "哈希对象错误"}; 
    pub const SAR_HASH_ERR:                  ErrorDefine = ErrorDefine {code: 0x0A000014, msg: "哈希运算错误"}; 
    pub const SAR_GEN_RSA_KEY_ERR:           ErrorDefine = ErrorDefine {code: 0x0A000015, msg: "生成RSA密钥错误"}; 
    pub const SAR_RSA_MODULES_LEN_ERR:       ErrorDefine = ErrorDefine {code: 0x0A000016, msg: "RSA密钥模块长度错误"}; 
    pub const SAR_CSP_IMPORT_PUBKEY_ERR:     ErrorDefine = ErrorDefine {code: 0x0A000017, msg: "CSP服务导入公钥错误"}; 
    pub const SAR_RSA_ENC_ERR:               ErrorDefine = ErrorDefine {code: 0x0A000018, msg: "RSA加密错误"}; 
    pub const SAR_RSA_DEC_ERR:               ErrorDefine = ErrorDefine {code: 0x0A000019, msg: "RSA解密错误"}; 
    pub const SAR_HASH_NOT_EQUAL_ERR:        ErrorDefine = ErrorDefine {code: 0x0A00001A, msg: "哈希值不相等"}; 
    pub const SAR_KEY_NOT_FOUND_ERR:         ErrorDefine = ErrorDefine {code: 0x0A00001B, msg: "密钥不存在"}; 
    pub const SAR_CERT_NOT_FOUND_ERR:        ErrorDefine = ErrorDefine {code: 0x0A00001C, msg: "证书不存在"}; 
    pub const SAR_NOT_EXPORT_ERR:            ErrorDefine = ErrorDefine {code: 0x0A00001D, msg: "对象未导出"}; 
    pub const SAR_DECRYPT_PAD_ERR:           ErrorDefine = ErrorDefine {code: 0x0A00001E, msg: "解密填充错误"}; 
    pub const SAR_MAC_LEN_ERR:               ErrorDefine = ErrorDefine {code: 0x0A00001F, msg: "MAC长度错误"}; 
    pub const SAR_BUFFER_TOO_SMALL:          ErrorDefine = ErrorDefine {code: 0x0A000020, msg: "缓冲区不足"}; 
    pub const SAR_KEY_INFO_TYPE_ERR:         ErrorDefine = ErrorDefine {code: 0x0A000021, msg: "密钥类型错误"}; 
    pub const SAR_NOT_EVENT_ERR:             ErrorDefine = ErrorDefine {code: 0x0A000022, msg: "无事件错误"}; 
    pub const SAR_DEVICE_REMOVED:            ErrorDefine = ErrorDefine {code: 0x0A000023, msg: "设备已移除"}; 
    pub const SAR_PIN_INCRRECT:              ErrorDefine = ErrorDefine {code: 0x0A000024, msg: "PIN不正确"};
    pub const SAR_PIN_LOCKED:                ErrorDefine = ErrorDefine {code: 0x0A000025, msg: "PIN锁定"};
    pub const SAR_PIN_INVALID:               ErrorDefine = ErrorDefine {code: 0x0A000026, msg: "PIN无效"};
    pub const SAR_PIN_LEN_RANGE:             ErrorDefine = ErrorDefine {code: 0x0A000027, msg: "PIN长度错误"};
    pub const SAR_USER_ALREADY_LOGGED_IN:    ErrorDefine = ErrorDefine {code: 0x0A000028, msg: "用户已登录"};
    pub const SAR_USER_PIN_NOT_INITIALIZED:  ErrorDefine = ErrorDefine {code: 0x0A000029, msg: "用户口令未初始化"};
    pub const SAR_USER_TYPE_INVALID:         ErrorDefine = ErrorDefine {code: 0x0A00002A, msg: "PIN类型错误"};
    pub const SAR_APPLICATION_NAME_INVALID:  ErrorDefine = ErrorDefine {code: 0x0A00002B, msg: "应用名称无效"};
    pub const SAR_APPLICATION_EXISTS:        ErrorDefine = ErrorDefine {code: 0x0A00002C, msg: "应用已存在"};
    pub const SAR_USER_NOT_LOGGED_IN:        ErrorDefine = ErrorDefine {code: 0x0A00002D, msg: "用户未登录"};
    pub const SAR_APPLICATION_NOT_EXISTS:    ErrorDefine = ErrorDefine {code: 0x0A00002E, msg: "应用不存在"};
    pub const SAR_FILE_ALREADY_EXISTS:       ErrorDefine = ErrorDefine {code: 0x0A00002F, msg: "文件已存在"};
    pub const SAR_NO_ROOM:                   ErrorDefine = ErrorDefine {code: 0x0A000030, msg: "空间不足"};
    pub const SAR_FILE_NOT_EXISTS:           ErrorDefine = ErrorDefine {code: 0x0A000031, msg: "文件不存在"};
    pub const SAR_REACH_MAX_CONTAINER_COUNT: ErrorDefine = ErrorDefine {code: 0x0A000032, msg: "已达到容器上限"};
    // 扩展错误码
    pub const SAR_AUTH_BLOCKED:              ErrorDefine = ErrorDefine {code: 0x0A000033, msg: "密钥已锁定"};
    pub const SAR_INVALID_CONTAINER:         ErrorDefine = ErrorDefine {code: 0x0A000035, msg: "无效容器"};
    pub const SAR_CONTAINER_NOT_EXISTS:      ErrorDefine = ErrorDefine {code: 0x0A000036, msg: "容器不存在"};
    pub const SAR_CONTAINER_EXISTS:          ErrorDefine = ErrorDefine {code: 0x0A000037, msg: "容器已存在"};
    pub const SAR_KEY_NOUSAGE_ERR:           ErrorDefine = ErrorDefine {code: 0x0A000039, msg: "密钥未使用"};
    pub const SAR_FILE_ATTRIBUTE_ERR:        ErrorDefine = ErrorDefine {code: 0x0A00003A, msg: "文件操作权限错误"};
    pub const SAR_DEV_NO_AUTH:               ErrorDefine = ErrorDefine {code: 0x0A00003B, msg: "设备未认证"};

    const ERROR_DEFINES: [ErrorDefine; 59] = [
        ErrorCodes::SAR_OK, ErrorCodes::SAR_FAIL, ErrorCodes::SAR_UNKNOWN_ERR, ErrorCodes::SAR_NOT_SUPPORT_YET_ERR,
        ErrorCodes::SAR_FILE_ERR, ErrorCodes::SAR_INVALID_HANDLE_ERR, ErrorCodes::SAR_INVALID_PARAM1_ERR, ErrorCodes::SAR_READ_FILE_ERR,
        ErrorCodes::SAR_WRITE_FILE_ERR, ErrorCodes::SAR_NAME_LEN_ERR, ErrorCodes::SAR_KEY_USAGE_ERR, ErrorCodes::SAR_MODULES_LEN_ERR,
        ErrorCodes::SAR_NOT_INITIALIZE_ERR, ErrorCodes::SAR_OBJ_ERR, ErrorCodes::SAR_MEMORY_ERR, ErrorCodes::SAR_TIMEOUT_ERR,
        ErrorCodes::SAR_IN_DATALEN_ERR, ErrorCodes::SAR_IN_DATA_ERR, ErrorCodes::SAR_GEN_RAND_ERR, ErrorCodes::SAR_HASH_OBJ_ERR,
        ErrorCodes::SAR_HASH_ERR, ErrorCodes::SAR_GEN_RSA_KEY_ERR, ErrorCodes::SAR_RSA_MODULES_LEN_ERR, ErrorCodes::SAR_CSP_IMPORT_PUBKEY_ERR,
        ErrorCodes::SAR_RSA_ENC_ERR, ErrorCodes::SAR_RSA_DEC_ERR, ErrorCodes::SAR_HASH_NOT_EQUAL_ERR, ErrorCodes::SAR_KEY_NOT_FOUND_ERR,
        ErrorCodes::SAR_CERT_NOT_FOUND_ERR, ErrorCodes::SAR_NOT_EXPORT_ERR, ErrorCodes::SAR_DECRYPT_PAD_ERR, ErrorCodes::SAR_MAC_LEN_ERR,
        ErrorCodes::SAR_BUFFER_TOO_SMALL, ErrorCodes::SAR_KEY_INFO_TYPE_ERR, ErrorCodes::SAR_NOT_EVENT_ERR, ErrorCodes::SAR_DEVICE_REMOVED,
        ErrorCodes::SAR_PIN_INCRRECT, ErrorCodes::SAR_PIN_LOCKED, ErrorCodes::SAR_PIN_INVALID, ErrorCodes::SAR_PIN_LEN_RANGE,
        ErrorCodes::SAR_USER_ALREADY_LOGGED_IN, ErrorCodes::SAR_USER_PIN_NOT_INITIALIZED, ErrorCodes::SAR_USER_TYPE_INVALID, ErrorCodes::SAR_APPLICATION_NAME_INVALID,
        ErrorCodes::SAR_APPLICATION_EXISTS, ErrorCodes::SAR_USER_NOT_LOGGED_IN, ErrorCodes::SAR_APPLICATION_NOT_EXISTS, ErrorCodes::SAR_FILE_ALREADY_EXISTS,
        ErrorCodes::SAR_NO_ROOM, ErrorCodes::SAR_FILE_NOT_EXISTS, ErrorCodes::SAR_REACH_MAX_CONTAINER_COUNT, ErrorCodes::SAR_AUTH_BLOCKED,
        ErrorCodes::SAR_INVALID_CONTAINER, ErrorCodes::SAR_CONTAINER_NOT_EXISTS, ErrorCodes::SAR_CONTAINER_EXISTS, ErrorCodes::SAR_KEY_NOUSAGE_ERR,
        ErrorCodes::SAR_FILE_ATTRIBUTE_ERR, ErrorCodes::SAR_DEV_NO_AUTH, ErrorCodes::SAR_INVALID_PARAM2_ERR,
    ];

    /// 根据编码获取错误定义对象
    /// # 返回值
    /// 返回错误定义结构对象
    pub fn get_error(code: c_long) -> ErrorDefine {
        for error in &(ErrorCodes::ERROR_DEFINES) {
            if error.code == code {
                return ErrorDefine {code: error.code, msg: error.msg};
            }
        }
        ErrorDefine {code, msg: "未知错误"}
    }
    /// 判断是否返回成功
    pub fn is_ok(code: c_long) -> bool {
        return code == ErrorCodes::SAR_OK.code;
    }
}
