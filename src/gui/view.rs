//! Main window layout, journal and frame updates.
use super::widgets::{caption, pill, tint};
use super::{App, Level, Notice, SCAN_INTERVAL, Tone, UI_REFRESH_INTERVAL};
use eframe::egui::{self, Color32, RichText, Vec2};
use std::time::Instant;
use zalivka::localization::{format as trf, text as tr};

impl App {
    pub(super) fn header(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        egui::Panel::top("header")
            .frame(
                egui::Frame::new()
                    .fill(ui.visuals().window_fill)
                    .inner_margin(egui::Margin::symmetric(26, 15)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let logo = self.logo.get_or_insert_with(|| {
                        let icon = super::logo_icon();
                        ctx.load_texture(
                            "zalivka-logo",
                            egui::ColorImage::from_rgba_unmultiplied(
                                [icon.width as usize, icon.height as usize],
                                &icon.rgba,
                            ),
                            egui::TextureOptions::LINEAR,
                        )
                    });
                    ui.add(
                        egui::Image::new(&*logo)
                            .fit_to_exact_size(Vec2::new(56.0, 44.0))
                            .alt_text(tr("Zalivka logo")),
                    );
                    ui.label(RichText::new(tr("Zalivka")).size(20.0).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button(tr("Settings")).clicked() {
                            self.settings_open = true;
                        }
                        if ui
                            .selectable_label(
                                self.journal_open,
                                RichText::new(tr("Journal")).color(if self.journal_open {
                                    Color32::WHITE
                                } else {
                                    ui.visuals().text_color()
                                }),
                            )
                            .clicked()
                        {
                            self.journal_open = !self.journal_open;
                        }
                    });
                });
            });
    }
    pub(super) fn journal(&mut self, ui: &mut egui::Ui) {
        if !self.journal_open {
            return;
        }
        let ctx = ui.ctx().clone();
        let margin: i8 = if ctx.content_rect().height() < 700.0 {
            8
        } else {
            16
        };
        let header_id = ui.scope_id().with("journal_header_height");
        let header_height = ctx
            .data(|data| data.get_temp::<f32>(header_id))
            .unwrap_or(24.0);
        let row_spacing = 2.0;
        let separator_spacing = 1.0;
        let log_font = egui::FontId::monospace(12.0);
        // Allocate the same padded row height that show_rows uses for scrolling.
        // One physical pixel on either side also covers text paint rounding.
        let pixels_per_point = ctx.pixels_per_point();
        let row_height = (ui.fonts_mut(|fonts| fonts.row_height(&log_font)) * pixels_per_point)
            .ceil()
            / pixels_per_point
            + 2.0 / pixels_per_point;
        let minimum_height = header_height
            + row_height
            + 2.0 * f32::from(margin)
            + 2.0 * row_spacing
            + separator_spacing;
        let max_height = (ctx.content_rect().height() * 0.35)
            .min(350.0)
            .min((ui.available_height() - if self.job.is_none() { 160.0 } else { 80.0 }).max(70.0))
            .max(minimum_height);
        egui::Panel::bottom("journal")
            .resizable(true)
            .default_size(max_height.min(220.0))
            .min_size(max_height.min(110.0).max(minimum_height))
            .max_size(max_height)
            .frame(
                egui::Frame::new()
                    .fill(ui.visuals().window_fill)
                    .inner_margin(margin),
            )
            .show(ui, |ui| {
                ui.spacing_mut().interact_size.y = 24.0;
                ui.spacing_mut().item_spacing.y = row_spacing;
                let actions_width = ["Open logs folder", "Copy", "Hide"]
                    .into_iter()
                    .map(|label| {
                        ui.painter()
                            .layout_no_wrap(
                                tr(label),
                                egui::TextStyle::Button.resolve(ui.style()),
                                ui.visuals().text_color(),
                            )
                            .size()
                            .x
                            + 2.0 * ui.spacing().button_padding.x
                    })
                    .sum::<f32>()
                    + 2.0 * ui.spacing().item_spacing.x;
                let header = ui.horizontal_wrapped(|ui| {
                    ui.strong(tr("Journal"));
                    ui.checkbox(&mut self.log_details, tr("Technical details"));
                    if ui.available_size_before_wrap().x < actions_width {
                        ui.end_row();
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button(tr("Hide")).clicked() {
                            self.journal_open = false;
                        }
                        if ui
                            .add_enabled(
                                !self.logs.is_empty(),
                                egui::Button::new(tr("Copy")).small(),
                            )
                            .clicked()
                        {
                            ctx.copy_text(self.journal_text(self.log_details));
                        }
                        if ui.small_button(tr("Open logs folder")).clicked()
                            && let Err(error) = zalivka::storage::log_directory()
                                .and_then(|directory| zalivka::platform::open_directory(&directory))
                        {
                            self.error("Could not open the logs folder", format!("{error:#}"));
                        }
                    });
                });
                // Measure wrapping instead of assuming a single toolbar row:
                // translated controls can need more space after a window resize.
                let measured_height = header.response.rect.height();
                if (measured_height - header_height).abs() > 0.5 {
                    ctx.data_mut(|data| data.insert_temp(header_id, measured_height));
                    ctx.request_repaint();
                }
                ui.add(egui::Separator::default().spacing(separator_spacing));
                let records: Vec<_> = self
                    .logs
                    .iter()
                    .filter(|record| self.log_details || record.level >= Level::Info)
                    .collect();
                if records.is_empty() {
                    ui.label(
                        RichText::new(tr("Operation progress will appear here."))
                            .color(ui.visuals().weak_text_color()),
                    );
                }
                egui::ScrollArea::both()
                    .auto_shrink([false, false])
                    // Wrapped journal controls must leave at least one log row visible.
                    .min_scrolled_height(row_height)
                    .stick_to_bottom(true)
                    .show_rows(ui, row_height, records.len(), |ui, rows| {
                        for row in rows {
                            let record = records[row];
                            let color = match record.level {
                                Level::Error => ui.visuals().error_fg_color,
                                Level::Warning => ui.visuals().warn_fg_color,
                                Level::Info => ui.visuals().text_color(),
                                Level::Trace | Level::Debug => ui.visuals().weak_text_color(),
                            };
                            ui.add_sized(
                                [ui.available_width(), row_height],
                                egui::Label::new(
                                    RichText::new(record.to_string())
                                        .font(log_font.clone())
                                        .color(color),
                                )
                                .halign(egui::Align::Min)
                                .wrap_mode(egui::TextWrapMode::Extend),
                            );
                        }
                    });
            });
    }

    fn notification(&mut self, ctx: &egui::Context, bounds: egui::Rect) {
        let Some(notice) = &self.notice else { return };
        if let Some(deadline) = notice.expires_at {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.notice = None;
                return;
            }
            ctx.request_repaint_after(remaining);
        }
        let mut dismiss = false;
        egui::Area::new(egui::Id::unique("notification"))
            .order(egui::Order::Foreground)
            .movable(false)
            .anchor(egui::Align2::RIGHT_TOP, Vec2::ZERO)
            .constrain_to(bounds)
            .show(ctx, |ui| {
                let color = match notice.tone {
                    Tone::Neutral => ui.visuals().hyperlink_color,
                    tone => tone.color(ui.visuals()),
                };
                let frame = egui::Frame::popup(ui.style())
                    .corner_radius(12)
                    .inner_margin(14)
                    .stroke(egui::Stroke::new(
                        1.0_f32,
                        tint(color, ui.visuals().window_fill),
                    ));
                let width = bounds.width().min(420.0) - frame.total_margin().sum().x;
                frame.show(ui, |ui| {
                    ui.set_width(width);
                    ui.horizontal_top(|ui| {
                        pill(
                            ui,
                            match notice.tone {
                                Tone::Neutral => "i",
                                Tone::Success => "✓",
                                Tone::Error => "!",
                            },
                            color,
                        );
                        let text_width = ui.available_width() - 24.0 - ui.spacing().item_spacing.x;
                        ui.vertical(|ui| {
                            ui.set_width(text_width);
                            ui.add(
                                egui::Label::new(RichText::new(tr(&notice.title)).strong()).wrap(),
                            );
                            if !notice.detail.is_empty() || notice.journal_error.is_some() {
                                egui::ScrollArea::vertical()
                                    .id_salt("notification_detail")
                                    .max_height((bounds.height() - 110.0).clamp(24.0, 140.0))
                                    .show(ui, |ui| {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new({
                                                    let mut detail = tr(&notice.detail);
                                                    if let Some(error) = &notice.journal_error {
                                                        if !detail.is_empty() { detail.push(' '); }
                                                        detail.push_str(&trf("Disk journal incomplete: {error}. Recent history is available in this window.", &[error]));
                                                    }
                                                    detail
                                                })
                                                    .size(13.0)
                                                    .color(ui.visuals().weak_text_color()),
                                            )
                                            .wrap(),
                                        );
                                    });
                            }
                            if notice.tone == Tone::Error
                                && !self.logs.is_empty()
                                && ui.small_button(tr("Open journal")).clicked()
                            {
                                self.journal_open = true;
                            }
                        });
                        dismiss = ui
                            .add_sized(
                                [24.0, 24.0],
                                egui::Button::new(RichText::new(tr("×")).size(20.0)).frame(false),
                            )
                            .on_hover_text(tr("Dismiss notification"))
                            .clicked();
                    });
                });
            });
        if dismiss {
            self.notice = None;
        }
    }
}

impl App {
    pub(super) fn view(&mut self, ui: &mut egui::Ui) {
        let _language = self.localization.enter();
        let ctx = ui.ctx().clone();
        self.header(ui);
        egui::Panel::bottom("footer")
            .frame(
                egui::Frame::new()
                    .fill(ui.visuals().panel_fill)
                    .inner_margin(egui::Margin::symmetric(26, 9)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    caption(
                        ui,
                        if self.job.is_some() {
                            "Operation in progress"
                        } else if self.target().is_some() {
                            "Mac connected"
                        } else {
                            "Waiting for a device"
                        },
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add(
                            egui::Label::new(
                                RichText::new(trf("Zalivka {}", &[zalivka::VERSION]))
                                    .small()
                                    .color(ui.visuals().weak_text_color()),
                            )
                            .truncate(),
                        )
                        .on_hover_text(zalivka::VERSION);
                    });
                });
            });
        self.journal(ui);
        // Keep the operation buttons above the journal while the setup cards
        // scroll independently. Short windows get the same buttons without
        // the descriptive headings.
        let dock_actions = self.journal_open && self.job.is_none();
        if dock_actions {
            let compact = ctx.content_rect().height() < 700.0;
            egui::Panel::bottom("actions")
                .frame(
                    egui::Frame::new()
                        .fill(ui.visuals().panel_fill)
                        .inner_margin(egui::Margin::symmetric(22, 8)),
                )
                .show(ui, |ui| self.action_controls(ui, compact));
        }
        let mut notification_bounds = ctx.content_rect().shrink(14.0);
        notification_bounds.min.y = ui.available_rect_before_wrap().top() + 14.0;
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(ui.visuals().panel_fill)
                    .inner_margin(22),
            )
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("main_content")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.heading(tr("Mac restore"));
                        ui.add_space(9.0);
                        if self.job.is_some() {
                            self.active_job(ui);
                        } else {
                            ui.add_enabled_ui(!self.picking, |ui| {
                                self.windows_card(ui, &ctx);
                                if ui.available_width() >= 780.0 {
                                    ui.columns(2, |columns| {
                                        let mut device =
                                            self.prepare_device_card(&mut columns[0], &ctx);
                                        let mut firmware =
                                            self.prepare_firmware_card(&mut columns[1], &ctx);
                                        let height = device
                                            .content_ui
                                            .min_size()
                                            .y
                                            .max(firmware.content_ui.min_size().y);
                                        for frame in [&mut device, &mut firmware] {
                                            let mut bounds = frame.content_ui.min_rect();
                                            bounds.set_height(height);
                                            frame.content_ui.expand_to_include_rect(bounds);
                                        }
                                        device.end(&mut columns[0]);
                                        firmware.end(&mut columns[1]);
                                    });
                                } else {
                                    self.prepare_device_card(ui, &ctx).end(ui);
                                    ui.add_space(12.0);
                                    self.prepare_firmware_card(ui, &ctx).end(ui);
                                }
                                if !dock_actions {
                                    ui.add_space(12.0);
                                    self.actions(ui);
                                }
                            });
                        }
                    });
            });
        self.notification(&ctx, notification_bounds);
        self.settings(&ctx);
        self.confirmation(&ctx);
    }
}

impl eframe::App for App {
    fn clear_color(&self, visuals: &egui::Visuals) -> [f32; 4] {
        visuals.panel_fill.to_normalized_gamma_f32()
    }

    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        if self.job.is_none() && !self.picking && self.last_scan.elapsed() >= SCAN_INTERVAL {
            self.detect(ctx);
        }
        ctx.request_repaint_after(if self.job.is_some() {
            UI_REFRESH_INTERVAL
        } else {
            SCAN_INTERVAL
        });
        if ctx.input(|i| i.viewport().close_requested())
            && let Some(job) = &mut self.job
        {
            if !job.can_stop() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.notice = Some(Notice {
                    title: "Operation still in progress".into(),
                    detail: "Wait for the operation to finish before closing this window.".into(),
                    journal_error: None,
                    tone: Tone::Neutral,
                    expires_at: Some(Instant::now() + super::NOTICE_LIFETIME),
                });
            } else if let Err(error) = job.stop() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.error("Could not stop the operation", error);
            }
        }
        if self.job.is_none() && !self.picking && self.confirmation.is_none() {
            let dropped = ctx.input(|i| {
                i.raw
                    .dropped_files
                    .iter()
                    .map(|f| f.path().to_path_buf())
                    .find(|p| {
                        p.extension()
                            .is_some_and(|s| s.eq_ignore_ascii_case("ipsw"))
                    })
            });
            if let Some(path) = dropped {
                self.setup.ipsw = path.display().to_string();
                self.setup.automatic = false;
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.view(ui);
    }
}
