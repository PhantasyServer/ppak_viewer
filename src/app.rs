use crate::deriver::PacketStructDef;
use chrono::{DateTime, Local};
use egui::{InputState, Label};
use egui_extras::{Column, TableBuilder};
use pso2packetlib::{ppac::PacketData, protocol::Packet};

#[derive(PartialEq, PartialOrd, Clone, Copy)]
pub enum OutputFormat {
    Debug,
    Json,
    Hex,
    HexPretty,
}

pub struct TemplateApp {
    format: OutputFormat,
    values: Vec<String>,
    selected: Option<usize>,
    packets: Vec<PacketData<Packet>>,
    output: String,
    input: String,
    is_protocol_dev: bool,
    protocol_def_output: String,
    protocol_def: Option<PacketStructDef>,
}

impl Default for TemplateApp {
    fn default() -> Self {
        Self {
            format: OutputFormat::Debug,
            values: vec![],
            selected: None,
            packets: vec![],
            output: String::new(),
            input: String::new(),
            is_protocol_dev: false,
            protocol_def_output: String::new(),
            protocol_def: None,
        }
    }
}

impl TemplateApp {
    /// Called once before the first frame.
    pub fn new(_: &eframe::CreationContext<'_>) -> Self {
        // This is also where you can customize the look and feel of egui using
        // `cc.egui_ctx.set_visuals` and `cc.egui_ctx.set_fonts`.

        Default::default()
    }

    fn read_data(&mut self, i: &InputState) -> Result<(), Box<dyn std::error::Error>> {
        for file in &i.raw.dropped_files {
            let data = if let Some(data) = &file.bytes {
                data.clone()
            } else if let Some(path) = &file.path {
                std::fs::read(path)?.into()
            } else {
                return Ok(());
            };
            let mut reader = pso2packetlib::ppac::PPACReader::<_, Packet>::open(&*data)?;
            reader.set_out_type(pso2packetlib::ppac::OutputType::Both);
            self.packets.clear();
            self.values.clear();
            while let Some(packet) = reader.read()? {
                let date = DateTime::from_timestamp_nanos(packet.time.as_nanos() as i64)
                    .with_timezone(&Local);
                let value = format!(
                    "({}) ({}) {:02X?}",
                    date.format("%H:%M:%S%.f"),
                    match packet.direction {
                        pso2packetlib::ppac::Direction::ToServer => "C -> S",
                        pso2packetlib::ppac::Direction::ToClient => "S -> C",
                    },
                    &packet.data.as_ref().unwrap()[4..8],
                );
                self.values.push(value);
                self.packets.push(packet);
            }
        }
        Ok(())
    }
    fn format_output(packets: &[PacketData<Packet>], id: usize, format: OutputFormat) -> String {
        let packet = &packets[id];
        match format {
            OutputFormat::Debug => format!("{:#?}", packet.packet),
            OutputFormat::Json => match serde_json::to_string_pretty(&packet.packet) {
                Ok(v) => v,
                Err(e) => format!("Failed to serialize to JSON: {}", e),
            },
            OutputFormat::Hex => {
                let mut out = String::new();
                for b in packet.data.as_ref().unwrap() {
                    out.push_str(&format!("{:02X}", b));
                }
                out
            }
            OutputFormat::HexPretty => {
                let mut out =
                    String::from("Address  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n\n");
                let mut i = 0;
                let mut ascii = String::new();
                for (wrote, b) in packet.data.as_ref().unwrap().iter().enumerate() {
                    if i >= 16 {
                        out.push_str(&ascii);
                        out.push('\n');
                        i = 0;
                        ascii.clear();
                    }
                    if wrote % 16 == 0 {
                        out.push_str(&format!("{:08X} ", wrote));
                    }
                    out.push_str(&format!("{:02X} ", b));
                    let ascii_char = char::from_u32(*b as u32).unwrap_or_default();
                    if ascii_char.is_ascii_graphic() {
                        ascii.push(ascii_char);
                    } else {
                        ascii.push('.');
                    }
                    i += 1;
                }
                for _ in i..16 {
                    out.push_str("   ");
                }
                out.push_str(&ascii);
                out
            }
        }
    }
    fn format_with_custom(&self) -> String {
        if let Some(def) = &self.protocol_def {
            if let Some(i) = &self.selected {
                match def.read_from_data(self.packets[*i].data.as_ref().unwrap(), 0, 0) {
                    Ok(p) => format!("{:#?}", p),
                    Err(e) => e.to_string(),
                }
            } else {
                String::new()
            }
        } else {
            "No packet format provided".to_string()
        }
    }
}

impl eframe::App for TemplateApp {
    /// Called each time the UI needs repainting, which may be many times per second.
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Put your widgets into a `SidePanel`, `TopBottomPanel`, `CentralPanel`, `Window` or `Area`.
        // For inspiration and more examples, go to https://emilk.github.io/egui

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            // The top panel is often a good place for a menu bar:

            egui::menu::bar(ui, |ui| {
                // NOTE: no File->Quit on web pages!
                let is_web = cfg!(target_arch = "wasm32");
                if !is_web {
                    ui.menu_button("File", |ui| {
                        if ui.button("Quit").clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                    ui.add_space(16.0);
                }

                egui::widgets::global_dark_light_mode_buttons(ui);
                ui.checkbox(&mut self.is_protocol_dev, "Enable packet development");
                ui.vertical_centered(|ui| ui.label("Drag and drop a file to open it."));
            });
        });

        egui::SidePanel::left("left panel")
            .default_width(ctx.available_rect().width() / 4.0)
            .min_width(ctx.available_rect().width() / 4.0)
            .max_width(ctx.available_rect().width() / 4.0)
            .resizable(false)
            .show(ctx, |ui| {
                let mut out = None;
                let mut sel = None;
                TableBuilder::new(ui)
                    .column(Column::remainder().clip(true))
                    .sense(egui::Sense::click())
                    .header(20.0, |mut header| {
                        header.col(|ui| {
                            ui.heading("Packets");
                        });
                    })
                    .body(|mut body| {
                        for (i, v) in self.values.iter().enumerate() {
                            body.row(20.0, |mut row| {
                                row.set_selected(self.selected.map(|x| x == i).unwrap_or(false));
                                row.col(|ui| {
                                    ui.add(Label::new(v).selectable(false));
                                });
                                if row.response().clicked() {
                                    sel = Some(i);
                                    out = Some(if !self.is_protocol_dev {
                                        Self::format_output(&self.packets, i, self.format)
                                    } else {
                                        self.format_with_custom()
                                    });
                                }
                            });
                        }
                    });
                if let Some(out) = out {
                    self.output = out;
                }
                if let Some(sel) = sel {
                    self.selected = Some(sel);
                    if let Some(def) = &mut self.protocol_def {
                        def.id_from_packet(
                            self.packets[self.selected.unwrap()].data.as_ref().unwrap(),
                            self.packets[self.selected.unwrap()].protocol_type,
                        );
                        self.output = self.format_with_custom();
                    }
                    if let Some(def) = &self.protocol_def {
                        self.protocol_def_output = def.to_string();
                    }
                }
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            // The central panel the region left after adding TopPanel's and SidePanel's
            let prev = self.format;
            if !self.is_protocol_dev {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.format, OutputFormat::Debug, "Debug");
                    ui.selectable_value(&mut self.format, OutputFormat::Json, "JSON");
                    ui.selectable_value(&mut self.format, OutputFormat::Hex, "Hex");
                    ui.selectable_value(&mut self.format, OutputFormat::HexPretty, "Hex (Pretty)");
                });
                ui.separator();
            } else {
                self.format = OutputFormat::Debug;
            }

            if prev != self.format && self.selected.is_some() {
                self.output = if !self.is_protocol_dev {
                    Self::format_output(&self.packets, self.selected.unwrap(), self.format)
                } else {
                    self.format_with_custom()
                }
            }

            ui.horizontal_top(|ui| {
                let width = ui.available_rect_before_wrap().size().x
                    / if self.is_protocol_dev { 2.1 } else { 1.0 };
                egui::ScrollArea::vertical()
                    .max_height(ui.available_height() - 50.0)
                    .show(ui, |ui| {
                        ui.vertical(|ui| {
                            ui.label("Packet output");
                            ui.add(
                                egui::widgets::TextEdit::multiline(&mut self.output)
                                    .code_editor()
                                    .min_size([width, 200.0].into())
                                    .desired_width(width),
                            );
                            if self.is_protocol_dev {
                                ui.label("Packet output (Hex)");
                                let mut out = if self.selected.is_some() {
                                    Self::format_output(
                                        &self.packets,
                                        self.selected.unwrap(),
                                        OutputFormat::HexPretty,
                                    )
                                } else {
                                    String::new()
                                };
                                ui.add(
                                    egui::widgets::TextEdit::multiline(&mut out)
                                        .code_editor()
                                        .min_size([width, 200.0].into())
                                        .desired_width(width),
                                );
                            }
                        });
                    });
                if self.is_protocol_dev {
                    egui::ScrollArea::vertical()
                        .id_source(100)
                        .max_height(ui.available_height() - 50.0)
                        .show(ui, |ui| {
                            ui.vertical(|ui| {
                                ui.label("Packet format input field");
                                if ui
                                    .add(
                                        egui::widgets::TextEdit::multiline(&mut self.input)
                                            .code_editor()
                                            .min_size([width, 200.0].into())
                                            .desired_width(width),
                                    )
                                    .changed()
                                {
                                    match PacketStructDef::from_str(&self.input) {
                                        Ok(d) => self.protocol_def = d,
                                        Err(e) => {
                                            self.protocol_def_output =
                                                format!("Failed to parse packet format: {e}");
                                            self.protocol_def = None;
                                        }
                                    }
                                    if let Some(def) = &mut self.protocol_def {
                                        if let Some(i) = self.selected {
                                            def.id_from_packet(
                                                self.packets[i].data.as_ref().unwrap(),
                                                self.packets[i].protocol_type,
                                            );
                                        }
                                        self.output = self.format_with_custom();
                                    }
                                    if let Some(def) = &self.protocol_def {
                                        self.protocol_def_output = def.to_string();
                                    }
                                }
                                ui.label("Packet format output field");
                                ui.add(
                                    egui::widgets::TextEdit::multiline(
                                        &mut self.protocol_def_output,
                                    )
                                    .code_editor()
                                    .min_size([width, 200.0].into())
                                    .desired_width(width),
                                )
                            })
                        });
                }
            });
            ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                ui.add(egui::github_link_file!(
                    "https://github.com/PhantasyServer/ppak_viewer/blob/master/",
                    "Source code."
                ));
                powered_by_egui_and_eframe(ui);
                egui::warn_if_debug_build(ui);
            });
        });
        ctx.input(|i| {
            if !i.raw.dropped_files.is_empty() {
                self.read_data(i).unwrap();
            }
        })
    }
}

fn powered_by_egui_and_eframe(ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.label("Powered by ");
        ui.hyperlink_to("egui", "https://github.com/emilk/egui");
        ui.label(" and ");
        ui.hyperlink_to(
            "eframe",
            "https://github.com/emilk/egui/tree/master/crates/eframe",
        );
        ui.label(".");
    });
}
