//! Profile format parsing and construction for DualSense Edge.
//!
//! Each profile is stored across 3 consecutive feature reports (64 bytes each = 192 bytes).
//! Reports 0x70-0x72 = Profile slot 0, 0x73-0x75 = slot 1, etc.
//!
//! CRC32 is computed over [0xA3, buffer0, buffer1, buffer2] and stored
//! in the last 4 bytes of buffer 2 (little-endian).

use crate::reports::hex_dump;
use colored::Colorize;
use serde::{Deserialize, Serialize};

/// Known stick response curve presets on the DualSense Edge.
/// The curve_id selects a preset, and the 6 curve bytes define control points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CurvePreset {
    Default,  // 0x00 — linear: [128, 128, 196, 196, 225, 225]
    Quick,    // 0x01 — aggressive: [38, 38, 122, 139, 255, 255]
    Precise,  // 0x02 — gentle: [70, 57, 134, 115, 196, 177]
    Steady,   // 0x03 — dampened: [62, 62, 120, 129, 197, 179]
    Digital,  // 0x04 — snap: [38, 38, 38, 75, 255, 255]
    Dynamic,  // 0x05 — balanced: [69, 57, 183, 198, 255, 255]
    Custom(u8),
}

impl CurvePreset {
    pub fn from_id(id: u8) -> Self {
        match id {
            0x00 => Self::Default,
            0x01 => Self::Quick,
            0x02 => Self::Precise,
            0x03 => Self::Steady,
            0x04 => Self::Digital,
            0x05 => Self::Dynamic,
            other => Self::Custom(other),
        }
    }

    pub fn to_id(&self) -> u8 {
        match self {
            Self::Default => 0x00,
            Self::Quick => 0x01,
            Self::Precise => 0x02,
            Self::Steady => 0x03,
            Self::Digital => 0x04,
            Self::Dynamic => 0x05,
            Self::Custom(id) => *id,
        }
    }

    pub fn name(&self) -> String {
        match self {
            Self::Default => "Default".into(),
            Self::Quick => "Quick".into(),
            Self::Precise => "Precise".into(),
            Self::Steady => "Steady".into(),
            Self::Digital => "Digital".into(),
            Self::Dynamic => "Dynamic".into(),
            Self::Custom(id) => format!("Custom(0x{:02X})", id),
        }
    }

    /// Default 6-byte curve values for each preset
    pub fn default_curve_bytes(&self) -> [u8; 6] {
        match self {
            Self::Default => [128, 128, 196, 196, 225, 225],
            Self::Quick => [38, 38, 122, 139, 255, 255],
            Self::Precise => [70, 57, 134, 115, 196, 177],
            Self::Steady => [62, 62, 120, 129, 197, 179],
            Self::Digital => [38, 38, 38, 75, 255, 255],
            Self::Dynamic => [69, 57, 183, 198, 255, 255],
            Self::Custom(_) => [128, 128, 196, 196, 225, 225],
        }
    }
}

/// Stick curve data: modifier + 6 control points
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickCurve {
    pub preset: CurvePreset,
    pub modifier: u8,       // 0x03 or 0x04
    pub curve_bytes: [u8; 6], // 6 control points defining the response curve
}

/// Profile data decoded from 3 x 64-byte feature report buffers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileData {
    pub slot: u8,
    pub name: String,
    pub profile_id: [u8; 16],
    pub left_stick: StickCurve,
    pub right_stick: StickCurve,
    pub left_trigger_deadzone: (u8, u8),   // (min, max)
    pub right_trigger_deadzone: (u8, u8),  // (min, max)
    pub button_mapping: [u8; 16],
    pub crc32: u32,
}

/// Profile buffer layout offsets (within each 64-byte buffer)
///
/// Buffer 0 (name):
///   [0]    = profile button selector (0x00=unassigned, 0x60-0x63 for FN combos)
///   [1]    = unassigned flag (0x10 = empty slot) or 0x00
///   [2]    = always 1
///   [6..59] = UTF-16LE profile name (every other byte)
///
/// Buffer 1 (curves + profile ID):
///   [0]    = profile button selector (same as buf0)
///   [1]    = buffer index (always 1)
///   [28..44] = 16-byte profile UUID
///   [44]   = left stick modifier (0x03 or 0x04)
///   [47..53] = left stick 6 curve bytes
///   [53]   = right stick modifier
///   [56..60] = right stick curve bytes [0..4]
///
/// Buffer 2 (deadzones + buttons + CRC):
///   [0]    = profile button selector
///   [1]    = buffer index (always 2)
///   [2..4] = right stick curve bytes [4..6]
///   [4]    = left trigger deadzone min
///   [5]    = left trigger deadzone max
///   [6]    = right trigger deadzone min
///   [7]    = right trigger deadzone max
///   [10..26] = button remapping table (16 bytes)
///   [30]   = left joystick curve preset ID
///   [32]   = right joystick curve preset ID
///   [56..60] = CRC32 (little-endian)

impl ProfileData {
    /// Parse profile from 3 consecutive 64-byte buffers.
    /// Each buffer includes the report ID as byte 0.
    pub fn from_buffers(slot: u8, buf0: &[u8], buf1: &[u8], buf2: &[u8]) -> Option<Self> {
        if buf0.len() < 64 || buf1.len() < 64 || buf2.len() < 64 {
            return None;
        }

        // Skip report ID byte — offsets in the research are relative to the
        // data portion after the report ID.  But in our raw USB reads the
        // first byte IS the report ID, so buffer offsets from the community
        // RE map 1:1 to our array indices (byte[0] = report_id, byte[1] = first data byte).

        // Parse name from buf0[6..] — UTF-16LE
        let name = parse_utf16le_name(&buf0[6..60]);

        // Parse profile UUID from buf1[28..44]
        let mut profile_id = [0u8; 16];
        profile_id.copy_from_slice(&buf1[28..44]);

        // Left stick: modifier at buf1[44], curve bytes at buf1[47..53]
        let left_modifier = buf1[44];
        let mut left_curve = [0u8; 6];
        left_curve.copy_from_slice(&buf1[47..53]);

        // Right stick: modifier at buf1[53], curve bytes at buf1[56..60] + buf2[2..4]
        let right_modifier = buf1[53];
        let mut right_curve = [0u8; 6];
        right_curve[0..4].copy_from_slice(&buf1[56..60]);
        right_curve[4..6].copy_from_slice(&buf2[2..4]);

        // Left stick curve preset ID at buf2[30]
        let left_preset_id = buf2[30];
        // Right stick curve preset ID at buf2[32]
        let right_preset_id = buf2[32];

        // Trigger deadzones
        let left_trigger_dz = (buf2[4], buf2[5]);
        let right_trigger_dz = (buf2[6], buf2[7]);

        // Button mapping at buf2[10..26]
        let mut button_mapping = [0u8; 16];
        button_mapping.copy_from_slice(&buf2[10..26]);

        // CRC32 at buf2[56..60]
        let crc32 = u32::from_le_bytes([buf2[56], buf2[57], buf2[58], buf2[59]]);

        Some(ProfileData {
            slot,
            name,
            profile_id,
            left_stick: StickCurve {
                preset: CurvePreset::from_id(left_preset_id),
                modifier: left_modifier,
                curve_bytes: left_curve,
            },
            right_stick: StickCurve {
                preset: CurvePreset::from_id(right_preset_id),
                modifier: right_modifier,
                curve_bytes: right_curve,
            },
            left_trigger_deadzone: left_trigger_dz,
            right_trigger_deadzone: right_trigger_dz,
            button_mapping,
            crc32,
        })
    }

    /// Display a human-readable summary of the profile
    pub fn display(&self) {
        println!("{}", format!("  Profile Slot {}: \"{}\"", self.slot, self.name).cyan().bold());

        let uuid_hex: Vec<String> = self.profile_id.iter().map(|b| format!("{:02X}", b)).collect();
        println!("    UUID: {}", uuid_hex.join(""));

        // Left stick
        println!(
            "    Left Stick:  {} (id=0x{:02X}, modifier=0x{:02X})",
            self.left_stick.preset.name().green(),
            self.left_stick.preset.to_id(),
            self.left_stick.modifier
        );
        println!(
            "      Curve points: [{}, {}, {}, {}, {}, {}]",
            self.left_stick.curve_bytes[0],
            self.left_stick.curve_bytes[1],
            self.left_stick.curve_bytes[2],
            self.left_stick.curve_bytes[3],
            self.left_stick.curve_bytes[4],
            self.left_stick.curve_bytes[5],
        );

        // Right stick
        println!(
            "    Right Stick: {} (id=0x{:02X}, modifier=0x{:02X})",
            self.right_stick.preset.name().green(),
            self.right_stick.preset.to_id(),
            self.right_stick.modifier
        );
        println!(
            "      Curve points: [{}, {}, {}, {}, {}, {}]",
            self.right_stick.curve_bytes[0],
            self.right_stick.curve_bytes[1],
            self.right_stick.curve_bytes[2],
            self.right_stick.curve_bytes[3],
            self.right_stick.curve_bytes[4],
            self.right_stick.curve_bytes[5],
        );

        // Trigger deadzones
        println!(
            "    L2 Trigger DZ: min={}, max={}  (0x{:02X}-0x{:02X})",
            self.left_trigger_deadzone.0,
            self.left_trigger_deadzone.1,
            self.left_trigger_deadzone.0,
            self.left_trigger_deadzone.1,
        );
        println!(
            "    R2 Trigger DZ: min={}, max={}  (0x{:02X}-0x{:02X})",
            self.right_trigger_deadzone.0,
            self.right_trigger_deadzone.1,
            self.right_trigger_deadzone.0,
            self.right_trigger_deadzone.1,
        );

        // Button mapping
        let default_map: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let buttons = [
            "DPad-Up", "DPad-Left", "DPad-Down", "DPad-Right",
            "Circle", "Cross", "Square", "Triangle",
            "R1", "R2", "R3", "L1", "L2", "L3",
            "Paddle-L", "Paddle-R",
        ];
        let has_remaps = self.button_mapping != default_map;
        if has_remaps {
            println!("    Button Remaps:");
            for (i, &mapped_to) in self.button_mapping.iter().enumerate() {
                if mapped_to != i as u8 {
                    let from = buttons.get(i).unwrap_or(&"?");
                    let to = buttons.get(mapped_to as usize).unwrap_or(&"?");
                    println!("      {} -> {}", from, to);
                }
            }
        } else {
            println!("    Button Remaps: none (default)");
        }

        println!("    CRC32: 0x{:08X}", self.crc32);
    }

    /// Serialize profile back to 3 x 64-byte buffers for writing.
    /// `button_selector` is the FN combo byte (0x60-0x63 or 0x00).
    pub fn to_buffers(&self, button_selector: u8, base_report_id: u8) -> ([u8; 64], [u8; 64], [u8; 64]) {
        let mut buf0 = [0u8; 64];
        let mut buf1 = [0u8; 64];
        let mut buf2 = [0u8; 64];

        // Buffer 0: name
        buf0[0] = base_report_id;
        buf0[1] = button_selector;
        buf0[2] = 1; // always 1
        write_utf16le_name(&self.name, &mut buf0[6..60]);

        // Buffer 1: curves + profile ID
        buf1[0] = base_report_id + 1;
        buf1[1] = 1; // buffer index
        buf1[28..44].copy_from_slice(&self.profile_id);
        buf1[44] = self.left_stick.modifier;
        buf1[47..53].copy_from_slice(&self.left_stick.curve_bytes);
        buf1[53] = self.right_stick.modifier;
        buf1[56..60].copy_from_slice(&self.right_stick.curve_bytes[0..4]);

        // Buffer 2: deadzones, buttons, curve IDs, CRC
        buf2[0] = base_report_id + 2;
        buf2[1] = 2; // buffer index
        buf2[2..4].copy_from_slice(&self.right_stick.curve_bytes[4..6]);
        buf2[4] = self.left_trigger_deadzone.0;
        buf2[5] = self.left_trigger_deadzone.1;
        buf2[6] = self.right_trigger_deadzone.0;
        buf2[7] = self.right_trigger_deadzone.1;
        buf2[10..26].copy_from_slice(&self.button_mapping);
        buf2[30] = self.left_stick.preset.to_id();
        buf2[32] = self.right_stick.preset.to_id();

        // CRC32 over [0xA3, buf0, buf1, buf2_without_crc]
        let crc = compute_profile_crc(&buf0, &buf1, &buf2);
        buf2[56..60].copy_from_slice(&crc.to_le_bytes());

        (buf0, buf1, buf2)
    }
}

/// Parse UTF-16LE name from raw bytes, stopping at first null
fn parse_utf16le_name(data: &[u8]) -> String {
    let mut chars = Vec::new();
    for chunk in data.chunks(2) {
        if chunk.len() < 2 {
            break;
        }
        let c = u16::from_le_bytes([chunk[0], chunk[1]]);
        if c == 0 {
            break;
        }
        if let Some(ch) = char::from_u32(c as u32) {
            chars.push(ch);
        }
    }
    chars.into_iter().collect()
}

/// Write UTF-16LE name into buffer
fn write_utf16le_name(name: &str, buf: &mut [u8]) {
    buf.fill(0);
    for (i, ch) in name.encode_utf16().enumerate() {
        let offset = i * 2;
        if offset + 1 >= buf.len() {
            break;
        }
        let bytes = ch.to_le_bytes();
        buf[offset] = bytes[0];
        buf[offset + 1] = bytes[1];
    }
}

/// Compute CRC32 for profile data (read-back validation).
/// Algorithm: CRC-32/ISO-HDLC (standard) with NO seed byte.
/// Scope: buf0[2..60] + buf1[2..60] + buf2[2..56] = 170 bytes.
/// This is the CRC the device returns at buf2[56..60] on read.
pub fn compute_profile_crc(buf0: &[u8; 64], buf1: &[u8; 64], buf2: &[u8; 64]) -> u32 {
    use crc::{Crc, CRC_32_ISO_HDLC};
    let crc_algo = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    let mut digest = crc_algo.digest();
    digest.update(&buf0[2..60]);
    digest.update(&buf1[2..60]);
    digest.update(&buf2[2..56]);
    digest.finalize()
}

/// Compute per-buffer CRC32 for SET_FEATURE writes.
/// The device validates this CRC on each buffer during write.
/// Algorithm: CRC-32/ISO-HDLC over [0xA3, full_64_byte_buffer].
/// The CRC field (bytes 60-63) should be zeroed before computing.
/// Result is placed at bytes 60-63 (little-endian).
pub fn compute_write_crc(buf: &[u8; 64]) -> u32 {
    use crc::{Crc, CRC_32_ISO_HDLC};
    let crc_algo = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    let mut digest = crc_algo.digest();
    digest.update(&[0xA3]); // DualSense feature report seed
    digest.update(&buf[..60]); // Data before CRC field
    digest.update(&[0, 0, 0, 0]); // CRC field as zeros during computation
    digest.finalize()
}

/// Apply per-buffer write CRCs to all 3 profile buffers.
pub fn apply_write_crcs(buf0: &mut [u8; 64], buf1: &mut [u8; 64], buf2: &mut [u8; 64]) {
    let crc0 = compute_write_crc(buf0);
    buf0[60..64].copy_from_slice(&crc0.to_le_bytes());

    let crc1 = compute_write_crc(buf1);
    buf1[60..64].copy_from_slice(&crc1.to_le_bytes());

    let crc2 = compute_write_crc(buf2);
    buf2[60..64].copy_from_slice(&crc2.to_le_bytes());
}

/// Decode and display all profiles from a dump file
pub fn decode_profiles(dump_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read_to_string(dump_path)?;
    let dump: crate::reports::DeviceDump = serde_json::from_str(&data)?;

    // Build a map of report_id -> data
    let mut report_map = std::collections::HashMap::new();
    for r in &dump.reports {
        report_map.insert(r.report_id, r.data.as_slice());
    }

    let profile_bases: [(u8, &str); 4] = [
        (0x70, "Slot 0"),
        (0x73, "Slot 1"),
        (0x76, "Slot 2"),
        (0x79, "Slot 3"),
    ];

    println!("{}", "=== DualSense Edge Profile Decode ===".cyan().bold());
    println!();

    for (base_id, slot_label) in &profile_bases {
        let buf0 = report_map.get(base_id);
        let buf1 = report_map.get(&(base_id + 1));
        let buf2 = report_map.get(&(base_id + 2));

        match (buf0, buf1, buf2) {
            (Some(b0), Some(b1), Some(b2)) => {
                let slot = (base_id - 0x70) / 3;
                if let Some(profile) = ProfileData::from_buffers(slot, b0, b1, b2) {
                    profile.display();

                    // Verify CRC
                    let mut b0_arr = [0u8; 64];
                    let mut b1_arr = [0u8; 64];
                    let mut b2_arr = [0u8; 64];
                    b0_arr[..b0.len().min(64)].copy_from_slice(&b0[..b0.len().min(64)]);
                    b1_arr[..b1.len().min(64)].copy_from_slice(&b1[..b1.len().min(64)]);
                    b2_arr[..b2.len().min(64)].copy_from_slice(&b2[..b2.len().min(64)]);
                    let computed = compute_profile_crc(&b0_arr, &b1_arr, &b2_arr);
                    if computed == profile.crc32 {
                        println!("    CRC: {} (computed 0x{:08X})", "VALID".green().bold(), computed);
                    } else {
                        println!(
                            "    CRC: {} (expected 0x{:08X}, computed 0x{:08X})",
                            "MISMATCH".red().bold(),
                            profile.crc32,
                            computed
                        );
                    }
                    // Show raw buffers for RE reference
                    println!("    Raw buffer 1 (curves):");
                    println!("{}", hex_dump(b1));
                    println!("    Raw buffer 2 (deadzones/buttons):");
                    println!("{}", hex_dump(b2));
                    println!();
                } else {
                    println!("  {} {}: failed to parse", slot_label, "ERROR".red());
                }
            }
            _ => {
                println!("  {} {}: reports not found in dump", slot_label, "MISSING".yellow());
            }
        }
    }

    Ok(())
}

/// CLI command: write a custom curve to a profile slot.
pub fn write_curve_cmd(
    slot: u8,
    stick: &str,
    curve_str: &str,
    modifier: u8,
    name: &str,
    base_dump: Option<&std::path::Path>,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::reports::hex_dump;

    // Parse curve bytes
    let curve_parts: Vec<u8> = curve_str
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<u8>()
                .map_err(|e| format!("Bad curve value '{}': {}", s.trim(), e))
        })
        .collect::<Result<Vec<_>, _>>()?;

    if curve_parts.len() != 6 {
        return Err(format!(
            "Curve must be exactly 6 values (got {}). Format: p1x,p1y,p2x,p2y,p3x,p3y",
            curve_parts.len()
        )
        .into());
    }

    let curve_bytes: [u8; 6] = [
        curve_parts[0],
        curve_parts[1],
        curve_parts[2],
        curve_parts[3],
        curve_parts[4],
        curve_parts[5],
    ];

    if slot > 3 {
        return Err("Slot must be 0-3".into());
    }

    let apply_left = stick == "left" || stick == "both";
    let apply_right = stick == "right" || stick == "both";

    println!("{}", "=== Write Custom Curve ===".cyan().bold());
    println!("  Slot: {}", slot);
    println!("  Name: \"{}\"", name);
    println!("  Stick: {}", stick);
    println!("  Modifier: 0x{:02X}", modifier);
    println!(
        "  Curve: [{}, {}, {}, {}, {}, {}]",
        curve_bytes[0], curve_bytes[1], curve_bytes[2],
        curve_bytes[3], curve_bytes[4], curve_bytes[5]
    );

    // Load base profile if provided, otherwise start from existing slot or defaults
    let base_id = 0x70 + slot * 3;
    let (mut buf0, mut buf1, mut buf2) = if let Some(dump_path) = base_dump {
        let data = std::fs::read_to_string(dump_path)?;
        let dump: crate::reports::DeviceDump = serde_json::from_str(&data)?;
        let mut rmap = std::collections::HashMap::new();
        for r in &dump.reports {
            rmap.insert(r.report_id, r.data.clone());
        }
        let b0 = rmap.get(&base_id).cloned().unwrap_or_else(|| vec![0u8; 64]);
        let b1 = rmap.get(&(base_id + 1)).cloned().unwrap_or_else(|| vec![0u8; 64]);
        let b2 = rmap.get(&(base_id + 2)).cloned().unwrap_or_else(|| vec![0u8; 64]);
        let mut a0 = [0u8; 64];
        let mut a1 = [0u8; 64];
        let mut a2 = [0u8; 64];
        a0[..b0.len().min(64)].copy_from_slice(&b0[..b0.len().min(64)]);
        a1[..b1.len().min(64)].copy_from_slice(&b1[..b1.len().min(64)]);
        a2[..b2.len().min(64)].copy_from_slice(&b2[..b2.len().min(64)]);
        println!("  Base: loaded from {}", dump_path.display());
        (a0, a1, a2)
    } else {
        // Build minimal profile from scratch
        let mut a0 = [0u8; 64];
        let mut a1 = [0u8; 64];
        let mut a2 = [0u8; 64];

        // Buffer 0: report ID + selector + constant + name
        a0[0] = base_id;
        a0[1] = 0x00; // no FN combo assigned
        a0[2] = 1;
        write_utf16le_name(name, &mut a0[6..60]);

        // Buffer 1: report ID + index
        a1[0] = base_id + 1;
        a1[1] = 1;

        // Buffer 2: report ID + index + default deadzones + default button mapping
        a2[0] = base_id + 2;
        a2[1] = 2;
        a2[4] = 0x00; // L2 DZ min
        a2[5] = 0xFF; // L2 DZ max
        a2[6] = 0x00; // R2 DZ min
        a2[7] = 0xFF; // R2 DZ max
        // Default button mapping (identity)
        for i in 0..16u8 {
            a2[10 + i as usize] = i;
        }
        a2[28] = 0xC0; // paddle flag

        println!("  Base: fresh profile (no base dump)");
        (a0, a1, a2)
    };

    // Update name in buf0
    write_utf16le_name(name, &mut buf0[6..60]);

    // Apply curve to left stick
    if apply_left {
        buf1[44] = modifier;
        buf1[47..53].copy_from_slice(&curve_bytes);
        // Custom curve preset ID — use 0x00 (Default) since we're overriding the bytes
        buf2[30] = 0x00;
        println!("  Applied to left stick");
    }

    // Apply curve to right stick
    if apply_right {
        buf1[53] = modifier;
        buf1[56..60].copy_from_slice(&curve_bytes[0..4]);
        buf2[2..4].copy_from_slice(&curve_bytes[4..6]);
        buf2[32] = 0x00;
        println!("  Applied to right stick");
    }

    // Compute combined CRC at buf2[56..60] (what the device returns on read)
    let crc = compute_profile_crc(&buf0, &buf1, &buf2);
    buf2[56..60].copy_from_slice(&crc.to_le_bytes());
    println!("  Read CRC32: 0x{:08X}", crc);

    // Compute per-buffer write CRCs at bytes 60-63 of each buffer
    // (the device validates these during SET_FEATURE)
    apply_write_crcs(&mut buf0, &mut buf1, &mut buf2);
    println!(
        "  Write CRCs: buf0=0x{:08X} buf1=0x{:08X} buf2=0x{:08X}",
        u32::from_le_bytes([buf0[60], buf0[61], buf0[62], buf0[63]]),
        u32::from_le_bytes([buf1[60], buf1[61], buf1[62], buf1[63]]),
        u32::from_le_bytes([buf2[60], buf2[61], buf2[62], buf2[63]]),
    );

    // Show what we'll write
    println!("\n  Buffer 0 (name):");
    println!("{}", hex_dump(&buf0));
    println!("  Buffer 1 (curves):");
    println!("{}", hex_dump(&buf1));
    println!("  Buffer 2 (deadzones/buttons/CRC):");
    println!("{}", hex_dump(&buf2));

    if dry_run {
        println!("\n{}", "DRY RUN — not writing to device.".yellow().bold());
        return Ok(());
    }

    println!(
        "\n{}",
        format!("Writing to slot {}...", slot).cyan().bold()
    );
    // Try hidraw first (more reliable, matches WebHID behavior), fall back to raw USB
    match crate::usb::write_profile_hidraw(slot, &buf0, &buf1, &buf2) {
        Ok(()) => {}
        Err(e) => {
            println!("  hidraw failed ({}), trying raw USB...", e);
            crate::usb::write_profile(slot, &buf0, &buf1, &buf2)?;
        }
    }
    println!("{}", "\nProfile written successfully!".green().bold());

    Ok(())
}
