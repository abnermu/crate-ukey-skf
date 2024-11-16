
mod skf_types;
mod skf_error;
mod skf_util;
mod skf_device;
mod skf_auth;
mod skf_application;
mod skf_file;
mod skf_container;
mod skf_alogrithm;

pub use skf_types::*;
pub use skf_error::*;
pub use skf_util::*;
pub use skf_device::*;
pub use skf_auth::*;
pub use skf_application::*;
pub use skf_file::*;
pub use skf_container::*;
pub use skf_alogrithm::*;

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