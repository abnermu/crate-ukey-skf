use std::{ffi::CString, os::raw::c_long, sync::{Arc, Mutex}};
use eframe::egui;
use super::*;

/// pin码校验结果
pub struct CheckPinResult {
    /// 尝试次数
    pub retry_count: c_long,
    /// 返回结果
    pub result: ErrorDefine,
}

/// 用户口令校验弹窗结构
struct CheckPinDialog {
    /// 用户口令值
    pin: String,
    /// 确认按钮是否可用
    confirm_enabled: bool,
    /// 可重试次数
    retry_count: usize,
    /// 是否显示错误提示
    show_tip: bool,
    /// 输出共享数据
    check_result: Arc<Mutex<bool>>,
}
impl CheckPinDialog {
    fn new(cc: &eframe::CreationContext<'_>, check_result: Arc<Mutex<bool>>) -> Self {
        // Customize egui here with cc.egui_ctx.set_fonts and cc.egui_ctx.set_visuals.
        // Restore app state using cc.storage (requires the "persistence" feature).
        // Use the cc.gl (a glow::Context) to create graphics shaders and buffers that you can use
        // for e.g. egui::PaintCallback.
        // 设置中文字体
        let mut fonts = eframe::egui::FontDefinitions::default();
        let mut font_name: &str = "msyh";
        let mut font_path: &str = "C:\\Windows\\Fonts\\msyh.ttc";
        if cfg!(target_os = "linux") {
            font_name = "Arial";
            font_path = "/usr/share/fonts/truetype/msttcorefonts/Arial.ttf";
        }
        else if cfg!(target_os = "macos") {
            font_name = "Arial";
            font_path = "/Library/Fonts/Arial.ttf";
        }
        if let Ok(font_bytes) = std::fs::read(std::path::Path::new(font_path)) {
            fonts.font_data.insert(font_name.to_owned(), egui::FontData::from_owned(font_bytes));
            fonts.families.get_mut(&egui::FontFamily::Proportional).unwrap().insert(0, font_name.to_owned());
        }
        cc.egui_ctx.set_fonts(fonts);
        Self {
            pin: String::from(""),
            confirm_enabled: false,
            retry_count: 0,
            show_tip: false,
            check_result,
        }
    }
    fn check_pin(&mut self, ui: &mut egui::Ui) {
        if self.pin.len() == 6 {
            self.confirm_enabled = false;
            if let Some(check_result) = crate::check_pin(&self.pin) {
                if check_result.result.is_ok() {
                    self.show_tip = false;
                    self.retry_count = 0;
                    *self.check_result.lock().unwrap() = true;
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
                else {
                    self.show_tip = true;
                    self.retry_count = check_result.retry_count as usize;
                    self.confirm_enabled = self.pin.len() == 6;
                }
            }
        }
    }
}
impl eframe::App for CheckPinDialog {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        egui::Rgba::TRANSPARENT.to_array()
    }
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let panel_frame = egui::Frame {
            fill: ctx.style().visuals.window_fill(),
            rounding: 10.0.into(),
            stroke: ctx.style().visuals.widgets.noninteractive.fg_stroke,
            outer_margin: 0.5.into(),
            ..Default::default()
        };
        egui::CentralPanel::default().frame(panel_frame).show(ctx, |ui| {
            // 绑定事件
            if ctx.input(|i| i.key_released(egui::Key::Enter)) {
                self.check_pin(ui);
            }
            // 个性化title-bar
            let app_rect = ui.max_rect();
            let title_bar_height = 32.0;
            let title_bar_rect = {
                let mut rect = app_rect;
                rect.max.y = rect.min.y + title_bar_height;
                rect
            };
            let painter = ui.painter();
            let title_bar_response = ui.interact(title_bar_rect, egui::Id::new("title_bar"), egui::Sense::click_and_drag());
            painter.text(title_bar_rect.center(), egui::Align2::CENTER_CENTER, "验证Ukey用户口令", egui::FontId::proportional(20.0), ui.style().visuals.text_color());
            painter.line_segment([
                title_bar_rect.left_bottom() + egui::vec2(1.0, 0.0),
                title_bar_rect.right_bottom() + egui::vec2(-1.0, 0.0)
            ], ui.visuals().widgets.noninteractive.bg_stroke);
            if title_bar_response.drag_started_by(egui::PointerButton::Primary) {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
            }
            ui.allocate_new_ui(egui::UiBuilder::new().max_rect(title_bar_rect).layout(egui::Layout::right_to_left(egui::Align::Center)), |ui| {
                ui.spacing_mut().item_spacing.x = 0.0;
                ui.visuals_mut().button_frame = false;
                ui.add_space(8.0);
            });

            // 内容区域填充
            let content_rect = {
                let mut rect = app_rect;
                rect.min.y = title_bar_rect.max.y;
                rect
            }.shrink(4.0);
            let spacing: f32 = 20.0;
            let mut content_ui = ui.new_child(egui::UiBuilder::new().max_rect(content_rect).layout(egui::Layout::top_down_justified(egui::Align::Center)));
            egui::Frame::default().show(&mut content_ui, |content_ui| {
                egui::Frame {
                    outer_margin: spacing.into(),
                    inner_margin: 0.0.into(),
                    rounding: 0.0.into(),
                    shadow: egui::Shadow::NONE,
                    fill: egui::Color32::TRANSPARENT,
                    stroke: egui::Stroke { width: 0.0, color:  egui::Color32::TRANSPARENT}
                }.show(content_ui, |content_ui| {
                    // 输入框
                    content_ui.horizontal(|content_ui| {
                        let label_pin = content_ui.label("请输入用户口令：");
                        let state_id_pwshown = ui.id().with("pw_shown");
                        let state_id_pwshownhint = ui.id().with("pw_shown_hint");
                        let state_id_pwshownicon = ui.id().with("pw_shown_icon");
                        let mut pw_shown = ui.data_mut(|d| {d.get_temp::<bool>(state_id_pwshown).unwrap_or(false)});
                        let mut pw_shown_hint = ui.data_mut(|d| d.get_temp::<&'static str>(state_id_pwshownhint).unwrap_or("显示密码"));
                        let mut pw_shown_icon = ui.data_mut(|d| d.get_temp::<&'static str>(state_id_pwshownicon).unwrap_or("🔓"));
                        content_ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |content_ui| {
                            let pw_showhide_icon = egui::SelectableLabel::new(true, pw_shown_icon);
                            if content_ui.add(pw_showhide_icon).on_hover_text(pw_shown_hint).clicked() {
                                pw_shown = !pw_shown;
                                pw_shown_hint = if pw_shown {"隐藏密码"} else {"显示密码"};
                                pw_shown_icon = if pw_shown {"🔒"} else {"🔓"};

                            }
                            let te_pin = egui::TextEdit::singleline(&mut self.pin).password(!pw_shown);
                            let response = content_ui.add_sized(content_ui.available_size(), te_pin).highlight().labelled_by(label_pin.id);
                            response.request_focus();
                            if response.changed() {
                                self.confirm_enabled = self.pin.len() == 6;
                            }
                        });
                        ui.data_mut(|d| {d.insert_temp(state_id_pwshown, pw_shown);});
                        ui.data_mut(|d| {d.insert_temp(state_id_pwshownhint, pw_shown_hint);});
                        ui.data_mut(|d| {d.insert_temp(state_id_pwshownicon, pw_shown_icon);});
                    });
                    // 提示信息
                    content_ui.vertical_centered(|content_ui| {
                        let lbl_tip = egui::Label::new(
                            egui::RichText::new(format!("口令错误，您还有{}次机会！", self.retry_count))
                                .color(egui::Color32::from_hex("#F56C6C").unwrap())
                        );
                        content_ui.add_visible(self.show_tip, lbl_tip);
                    });
                    // 确认取消按钮
                    content_ui.horizontal(|content_ui| {
                        let button_width = 80.0;
                        let button_height = 28.0;
                        let button_area_padding = 60.0;
                        let btn_ok = egui::Button::new(
                            egui::RichText::new("确认").color(egui::Color32::from_rgb(255, 255, 255))
                        ).fill(egui::Color32::from_rgb(64, 158, 255));
                        let rect_ok = egui::Rect::from_min_size(
                            content_ui.min_rect().min + egui::vec2(button_area_padding, 0.0), 
                            egui::vec2(button_width, button_height)
                        );
                        content_ui.add_enabled_ui(self.confirm_enabled, |content_ui| {
                            if content_ui.put(rect_ok, btn_ok).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                                self.check_pin(ui);
                            }
                        });
                        let btn_cancel = egui::Button::new(
                            egui::RichText::new("取消").color(egui::Color32::from_rgb(255, 255, 255))
                        ).fill(egui::Color32::from_rgb(64, 158, 255));
                        let rect_cancel = egui::Rect::from_min_size(
                            content_ui.min_rect().min + egui::vec2(button_area_padding + button_width + spacing, 0.0), 
                            egui::vec2(button_width, button_height)
                        );
                        if content_ui.put(rect_cancel, btn_cancel).on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                            *self.check_result.lock().unwrap() = false;
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                });
            });
        });
    }
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
    /// pin校验（pin类型：0管理员；1用户。这里只用用户类型）
    /// 主要内部使用，直接弹出密码输入框进行校验
    pub fn check_pin_dialog() -> bool {
        // 计算窗口居中位置
        let window_width: f32 = 340.0;
        let window_height: f32 = 150.0;
        let mut pos_x: f32 = window_width;
        let mut pos_y: f32 = window_height;
        if let Ok((scr_width, scr_height)) = screen_size::get_primary_screen_size() {
            pos_x = (scr_width as f32 - window_width) / 2.0;
            pos_y = (scr_height as f32 - window_height) / 2.0;
        }
        let native_options = eframe::NativeOptions{
            viewport: egui::ViewportBuilder::default()
                // 设置窗口尺寸并禁止修改
                .with_inner_size([window_width, window_height])
                .with_resizable(false)
                // 设置位置居中
                .with_position(egui::pos2(pos_x, pos_y))
                // 不显示标题栏和边框
                .with_decorations(false)
                // 保持在顶层
                .with_always_on_top()
                // 背景透明，实现圆角
                .with_transparent(true),
            ..Default::default()
        };
        let check_result = Arc::new(Mutex::new(false));
        if let Ok(()) = eframe::run_native(
            "验证Ukey用户口令", 
            native_options, 
            Box::new(|cc| Ok(Box::new(CheckPinDialog::new(cc, check_result.clone()))))
        ) {
            if let Ok(valid) = check_result.lock() {
                return valid.to_owned();
            }
        }
        false
    }
}