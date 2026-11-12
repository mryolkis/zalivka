//! Main window layout, journal and frame updates.
use super::widgets::{caption, pill, tint};
use super::{App, Level, Notice, Tone, UI_REFRESH_INTERVAL};
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
        let margin = egui::Margin::symmetric(12, 4);
        let row_spacing = 2.0;
        let separator_spacing = 1.0;
        let log_font = egui::FontId::monospace(12.0);
        let pixels_per_point = ctx.pixels_per_point();
        let row_height = (ui.fonts_mut(|fonts| fonts.row_height(&log_font)) * pixels_per_point)
            .ceil()
            / pixels_per_point
            + 2.0 / pixels_per_point;
        let toolbar_row_height = (ui.text_style_height(&egui::TextStyle::Body) + 8.0).max(28.0);
        let minimum_scroll_height = row_height.max(ui.text_style_height(&egui::TextStyle::Body));
        let toolbar_spacing = 4.0;
        let button_padding = Vec2::new(10.0, 4.0);
        let text_width = |text: egui::WidgetText| {
            text.into_galley(
                ui,
                Some(egui::TextWrapMode::Extend),
                f32::INFINITY,
                egui::TextStyle::Body,
            )
            .size()
            .x
        };
        let left_width = text_width(RichText::new(tr("Journal")).strong().into())
            + ui.spacing().item_spacing.x
            + (text_width(tr("Technical details").into())
                + ui.spacing().icon_width
                + ui.spacing().icon_spacing)
                .max(toolbar_row_height);
        let actions_width = ["Open logs folder", "Copy", "Hide"]
            .into_iter()
            .map(|label| text_width(tr(label).into()) + 2.0 * button_padding.x)
            .sum::<f32>()
            + 2.0 * ui.spacing().item_spacing.x;
        let wrapped = left_width + ui.spacing().item_spacing.x + actions_width + 2.0
            > ui.available_width() - margin.sum().x;
        // Compute the toolbar from this frame's width. Its previous measured
        // height must not feed back into the panel's next size.
        let toolbar_rows = if wrapped { 2 } else { 1 };
        let header_height = toolbar_rows as f32 * toolbar_row_height
            + (toolbar_rows - 1) as f32 * toolbar_spacing
            + margin.sum().y;
        // Reserve the horizontal scrollbar as well, so long messages cannot
        // consume the last visible row or grow the panel on a later frame.
        let minimum_height = header_height
            + minimum_scroll_height
            + margin.sum().y
            + ui.spacing().scroll.allocated_width()
            + separator_spacing
            + 1.0;
        let max_height = (ctx.content_rect().height() * 0.35)
            .min(350.0)
            .min((ui.available_height() - if self.job.is_none() { 160.0 } else { 80.0 }).max(70.0))
            .max(minimum_height);
        egui::Panel::bottom("journal")
            .resizable(true)
            .default_size(max_height.min(220.0))
            .min_size(max_height.min(110.0).max(minimum_height))
            .max_size(max_height)
            .frame(egui::Frame::new().fill(ui.visuals().window_fill))
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                egui::Frame::new().inner_margin(margin).show(ui, |ui| {
                    ui.spacing_mut().interact_size.y = toolbar_row_height;
                    ui.spacing_mut().button_padding = button_padding;
                    ui.spacing_mut().item_spacing.y = toolbar_spacing;
                    for row in 0..toolbar_rows {
                        ui.allocate_ui_with_layout(
                            Vec2::new(ui.available_width(), toolbar_row_height),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.set_min_height(toolbar_row_height);
                                if row == 0 {
                                    ui.strong(tr("Journal"));
                                    ui.checkbox(&mut self.log_details, tr("Technical details"));
                                }
                                if !wrapped || row == 1 {
                                    ui.allocate_ui_with_layout(
                                        Vec2::new(ui.available_width(), toolbar_row_height),
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui.button(tr("Hide")).clicked() {
                                                self.journal_open = false;
                                            }
                                            if ui
                                                .add_enabled(
                                                    !self.logs.is_empty(),
                                                    egui::Button::new(tr("Copy")),
                                                )
                                                .clicked()
                                            {
                                                ctx.copy_text(self.journal_text(self.log_details));
                                            }
                                            if ui.button(tr("Open logs folder")).clicked()
                                                && let Err(error) = zalivka::storage::log_directory(
                                                )
                                                .and_then(|directory| {
                                                    zalivka::platform::open_directory(&directory)
                                                })
                                            {
                                                self.error(
                                                    "Could not open the logs folder",
                                                    format!("{error:#}"),
                                                );
                                            }
                                        },
                                    );
                                }
                            },
                        );
                    }
                });
                ui.add(egui::Separator::default().spacing(separator_spacing));
                egui::Frame::new().inner_margin(margin).show(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = row_spacing;
                    let records: Vec<_> = self
                        .logs
                        .iter()
                        .filter(|record| self.log_details || record.level >= Level::Info)
                        .collect();
                    let scroll = egui::ScrollArea::both()
                        .id_salt("journal_rows")
                        .auto_shrink([false, false])
                        .min_scrolled_height(minimum_scroll_height)
                        .stick_to_bottom(true);
                    let output = if records.is_empty() {
                        scroll.show(ui, |ui| {
                            ui.label(
                                RichText::new(tr("Operation progress will appear here."))
                                    .color(ui.visuals().weak_text_color()),
                            );
                        })
                    } else {
                        scroll.show_rows(ui, row_height, records.len(), |ui, rows| {
                            for row in rows {
                                let record = records[row];
                                let color = match record.level {
                                    Level::Error => ui.visuals().error_fg_color,
                                    Level::Warning => ui.visuals().warn_fg_color,
                                    Level::Info => ui.visuals().text_color(),
                                    Level::Trace | Level::Debug => ui.visuals().weak_text_color(),
                                };
                                ui.allocate_ui_with_layout(
                                    Vec2::new(ui.available_width(), row_height),
                                    egui::Layout::left_to_right(egui::Align::Center),
                                    |ui| {
                                        ui.set_min_height(row_height);
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(record.to_string())
                                                    .font(log_font.clone())
                                                    .color(color),
                                            )
                                            .wrap_mode(egui::TextWrapMode::Extend),
                                        );
                                    },
                                );
                            }
                        })
                    };
                    // egui updates the sticky scroll offset after painting.
                    // Resolve a changed viewport in this frame, before it is shown.
                    let viewport_id = output.id.with("viewport_size");
                    let viewport = output.inner_rect.size();
                    let previous = ctx.data_mut(|data| {
                        let previous = data.get_temp::<Vec2>(viewport_id);
                        data.insert_temp(viewport_id, viewport);
                        previous
                    });
                    if previous != Some(viewport) {
                        ctx.request_discard("journal viewport resized");
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
        // A wrapped journal toolbar can leave little room in a short window.
        // Give the heading priority over decorative vertical padding.
        let content_margin = egui::Margin::symmetric(
            22,
            ((ui.available_height() - ui.text_style_height(&egui::TextStyle::Heading)) * 0.5)
                .clamp(0.0, 22.0) as i8,
        );
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(ui.visuals().panel_fill)
                    .inner_margin(content_margin),
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
        self.poll_usb(ctx);
        let scan_interval = self.scan_interval();
        if self.job.is_none()
            && !self.picking
            && (self.usb_scan_pending || self.last_scan.elapsed() >= scan_interval)
        {
            self.detect(ctx);
        }
        ctx.request_repaint_after(if self.job.is_some() {
            UI_REFRESH_INTERVAL
        } else {
            scan_interval
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
