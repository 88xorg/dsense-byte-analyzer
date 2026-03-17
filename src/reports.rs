use serde::{Deserialize, Serialize};
use std::fmt;

// Sony vendor ID
pub const SONY_VID: u16 = 0x054C;
// DualSense Edge product ID
pub const DUALSENSE_EDGE_PID: u16 = 0x0DF2;
// Regular DualSense product ID (for testing)
pub const DUALSENSE_PID: u16 = 0x0CE6;

/// A single captured feature report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureReport {
    pub report_id: u8,
    pub length: usize,
    pub data: Vec<u8>,
    pub timestamp: String,
}

/// A full dump of all feature reports from a device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceDump {
    pub device_name: String,
    pub serial: String,
    pub vid: u16,
    pub pid: u16,
    pub timestamp: String,
    pub reports: Vec<FeatureReport>,
}

/// Parsed DualSense USB input report (report ID 0x01)
#[derive(Debug, Clone)]
pub struct InputReport {
    pub report_id: u8,
    pub left_stick_x: u8,
    pub left_stick_y: u8,
    pub right_stick_x: u8,
    pub right_stick_y: u8,
    pub dpad: u8,
    pub buttons_a: u8, // square, cross, circle, triangle
    pub buttons_b: u8, // L1, R1, L2btn, R2btn, create, options, L3, R3
    pub buttons_c: u8, // PS, touchpad, mute, Fn, etc.
    pub l2_trigger: u8,
    pub r2_trigger: u8,
}

impl InputReport {
    /// Parse from raw USB input report bytes.
    /// USB reports start with report ID 0x01 followed by payload.
    pub fn from_usb_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }

        Some(Self {
            report_id: data[0],
            left_stick_x: data[1],
            left_stick_y: data[2],
            right_stick_x: data[3],
            right_stick_y: data[4],
            dpad: data[5] & 0x0F,
            buttons_a: (data[5] >> 4) & 0x0F,
            buttons_b: data[6],
            buttons_c: data[7],
            l2_trigger: data[8],
            r2_trigger: data[9],
        })
    }

    pub fn dpad_direction(&self) -> &str {
        match self.dpad {
            0 => "N",
            1 => "NE",
            2 => "E",
            3 => "SE",
            4 => "S",
            5 => "SW",
            6 => "W",
            7 => "NW",
            8 => "-",
            _ => "?",
        }
    }

    pub fn face_buttons(&self) -> String {
        let mut s = String::new();
        if self.buttons_a & 0x01 != 0 { s.push_str("□ "); }
        if self.buttons_a & 0x02 != 0 { s.push_str("✕ "); }
        if self.buttons_a & 0x04 != 0 { s.push_str("○ "); }
        if self.buttons_a & 0x08 != 0 { s.push_str("△ "); }
        if self.buttons_b & 0x01 != 0 { s.push_str("L1 "); }
        if self.buttons_b & 0x02 != 0 { s.push_str("R1 "); }
        if self.buttons_b & 0x04 != 0 { s.push_str("L2 "); }
        if self.buttons_b & 0x08 != 0 { s.push_str("R2 "); }
        if self.buttons_b & 0x10 != 0 { s.push_str("Create "); }
        if self.buttons_b & 0x20 != 0 { s.push_str("Options "); }
        if self.buttons_b & 0x40 != 0 { s.push_str("L3 "); }
        if self.buttons_b & 0x80 != 0 { s.push_str("R3 "); }
        if s.is_empty() { s.push('-'); }
        s.trim().to_string()
    }
}

impl fmt::Display for InputReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LS({:3},{:3}) RS({:3},{:3}) L2:{:3} R2:{:3} DPad:{:2} Btn:[{}]",
            self.left_stick_x, self.left_stick_y,
            self.right_stick_x, self.right_stick_y,
            self.l2_trigger, self.r2_trigger,
            self.dpad_direction(),
            self.face_buttons(),
        )
    }
}

/// Format bytes as a hex dump with offset markers
pub fn hex_dump(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        // Offset
        out.push_str(&format!("  {:04X}  ", i * 16));
        // Hex bytes
        for (j, byte) in chunk.iter().enumerate() {
            out.push_str(&format!("{:02X} ", byte));
            if j == 7 { out.push(' '); }
        }
        // Pad if last line is short
        if chunk.len() < 16 {
            for j in chunk.len()..16 {
                out.push_str("   ");
                if j == 7 { out.push(' '); }
            }
        }
        // ASCII
        out.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                out.push(*byte as char);
            } else {
                out.push('.');
            }
        }
        out.push_str("|\n");
    }
    out
}
