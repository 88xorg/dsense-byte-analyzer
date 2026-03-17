//! Raw USB access using libusb/rusb.
//! Bypasses macOS IOHIDManager to access all interfaces and send
//! GET_REPORT/SET_REPORT as USB control transfers.

use crate::reports::{hex_dump, DeviceDump, FeatureReport, DUALSENSE_EDGE_PID, DUALSENSE_PID, SONY_VID};
use colored::Colorize;
use std::fs;
use std::path::Path;
use std::time::Duration;

/// USB HID class request types
const USB_DIR_IN: u8 = 0x80;
const USB_DIR_OUT: u8 = 0x00;
const USB_TYPE_CLASS: u8 = 0x20;
const USB_RECIP_INTERFACE: u8 = 0x01;
const HID_GET_REPORT: u8 = 0x01;
const HID_SET_REPORT: u8 = 0x09;

/// Report types for wValue high byte
#[allow(dead_code)]
const HID_REPORT_TYPE_INPUT: u16 = 0x0100;
#[allow(dead_code)]
const HID_REPORT_TYPE_OUTPUT: u16 = 0x0200;
const HID_REPORT_TYPE_FEATURE: u16 = 0x0300;

/// Edge-specific profile report IDs
const EDGE_PROFILE_REPORTS: std::ops::RangeInclusive<u8> = 0x70..=0x7B;
const EDGE_EXTRA_REPORTS: &[u8] = &[0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x68];

/// Enumerate USB interfaces on the DualSense Edge
pub fn usb_discover() -> Result<(), Box<dyn std::error::Error>> {
    let devices = rusb::devices()?;

    let mut found = false;
    for device in devices.iter() {
        let desc = device.device_descriptor()?;
        if desc.vendor_id() != SONY_VID {
            continue;
        }
        if desc.product_id() != DUALSENSE_EDGE_PID && desc.product_id() != DUALSENSE_PID {
            continue;
        }

        found = true;
        let is_edge = desc.product_id() == DUALSENSE_EDGE_PID;
        let model = if is_edge { "DualSense Edge" } else { "DualSense" };

        println!("{}", format!("Found {} via raw USB", model).green().bold());
        println!("  Bus {:03} Device {:03}", device.bus_number(), device.address());
        println!("  VID:PID: {:04X}:{:04X}", desc.vendor_id(), desc.product_id());
        println!("  Configurations: {}", desc.num_configurations());

        for cfg_idx in 0..desc.num_configurations() {
            let config = device.config_descriptor(cfg_idx)?;
            println!(
                "\n  Configuration {} (value: {})",
                cfg_idx,
                config.number()
            );

            for iface in config.interfaces() {
                for iface_desc in iface.descriptors() {
                    let class_name = match iface_desc.class_code() {
                        1 => "Audio",
                        3 => "HID",
                        0xFF => "Vendor-Specific",
                        c => &format!("Class {}", c).leak(),
                    };

                    println!(
                        "    Interface {} Alt {} — {} (class={}, subclass={}, protocol={})",
                        iface_desc.interface_number(),
                        iface_desc.setting_number(),
                        class_name,
                        iface_desc.class_code(),
                        iface_desc.sub_class_code(),
                        iface_desc.protocol_code(),
                    );

                    for ep in iface_desc.endpoint_descriptors() {
                        let dir = if ep.address() & 0x80 != 0 {
                            "IN"
                        } else {
                            "OUT"
                        };
                        let transfer = match ep.transfer_type() {
                            rusb::TransferType::Interrupt => "Interrupt",
                            rusb::TransferType::Bulk => "Bulk",
                            rusb::TransferType::Isochronous => "Isochronous",
                            rusb::TransferType::Control => "Control",
                        };
                        println!(
                            "      EP 0x{:02X} {} {} maxpacket={}",
                            ep.address(),
                            dir,
                            transfer,
                            ep.max_packet_size(),
                        );
                    }
                }
            }
        }
    }

    if !found {
        eprintln!("No DualSense controllers found via USB.");
    }

    Ok(())
}

/// Dump feature reports from ALL HID interfaces using raw USB control transfers
pub fn usb_dump(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let devices = rusb::devices()?;

    let device = devices
        .iter()
        .find(|d| {
            let desc = d.device_descriptor().unwrap();
            desc.vendor_id() == SONY_VID
                && (desc.product_id() == DUALSENSE_EDGE_PID
                    || desc.product_id() == DUALSENSE_PID)
        })
        .ok_or("No DualSense controller found")?;

    let desc = device.device_descriptor()?;
    let is_edge = desc.product_id() == DUALSENSE_EDGE_PID;
    let model = if is_edge { "DualSense Edge" } else { "DualSense" };

    let mut handle = device.open()?;
    println!("Opened {} via raw USB", model);

    // Find all HID interfaces
    let config = device.active_config_descriptor()?;
    let mut hid_interfaces: Vec<u8> = Vec::new();

    for iface in config.interfaces() {
        for iface_desc in iface.descriptors() {
            if iface_desc.class_code() == 3 {
                // HID class
                hid_interfaces.push(iface_desc.interface_number());
            }
        }
    }

    if hid_interfaces.is_empty() {
        // Try all interfaces if none are HID class
        for iface in config.interfaces() {
            for iface_desc in iface.descriptors() {
                hid_interfaces.push(iface_desc.interface_number());
            }
        }
    }

    println!("HID interfaces found: {:?}", hid_interfaces);

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let mut all_reports = Vec::new();

    for &iface_num in &hid_interfaces {
        // Try to detach kernel driver (needed on Linux, harmless on macOS)
        let had_kernel_driver = match handle.kernel_driver_active(iface_num) {
            Ok(true) => {
                println!("  Detaching kernel driver from interface {}...", iface_num);
                handle.detach_kernel_driver(iface_num).ok();
                true
            }
            _ => false,
        };

        let claimed = handle.claim_interface(iface_num).is_ok();
        if !claimed {
            println!(
                "{}",
                format!("  Could not claim interface {} (may be in use by OS)", iface_num).yellow()
            );
            // Still try the control transfers — on macOS they may work without claiming
        }

        println!(
            "\n{}",
            format!("=== Interface {} ===", iface_num).cyan().bold()
        );

        let mut success = 0u32;
        let mut fail = 0u32;

        for report_id in 0x00..=0xFFu8 {
            if report_id % 32 == 0 {
                print!(
                    "\r  Scanning 0x{:02X}..0x{:02X} ({} found)  ",
                    report_id,
                    (report_id as u16 + 31).min(0xFF),
                    success
                );
                std::io::Write::flush(&mut std::io::stdout())?;
            }

            let mut buf = vec![0u8; 1024];

            // GET_REPORT: bmRequestType = 0xA1 (Device-to-host, Class, Interface)
            // bRequest = 0x01 (GET_REPORT)
            // wValue = (report_type << 8) | report_id
            // wIndex = interface number
            let request_type = USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE;
            let value = HID_REPORT_TYPE_FEATURE | report_id as u16;

            match handle.read_control(
                request_type,
                HID_GET_REPORT,
                value,
                iface_num as u16,
                &mut buf,
                Duration::from_millis(500),
            ) {
                Ok(len) if len > 0 => {
                    success += 1;
                    all_reports.push(FeatureReport {
                        report_id,
                        length: len,
                        data: buf[..len].to_vec(),
                        timestamp: chrono::Local::now().to_rfc3339(),
                    });
                }
                _ => {
                    fail += 1;
                }
            }
        }

        println!(
            "\r  Interface {}: {} reports found, {} failed/unsupported       ",
            iface_num, success, fail
        );

        // Print what we got from this interface
        for report in all_reports.iter().filter(|r| {
            // Only print reports we haven't shown yet (simple dedup by checking last added)
            true
        }) {
            // Only print reports from this interface scan
        }

        if claimed {
            handle.release_interface(iface_num).ok();
        }
        if had_kernel_driver {
            handle.attach_kernel_driver(iface_num).ok();
        }
    }

    // Print all reports
    println!("\n{}", "=== All Reports ===".cyan().bold());
    for report in &all_reports {
        println!(
            "{}",
            format!("Report 0x{:02X} ({} bytes):", report.report_id, report.length)
                .green()
                .bold()
        );
        println!("{}", hex_dump(&report.data));
    }

    // Save
    fs::create_dir_all(output_dir)?;
    let dump = DeviceDump {
        device_name: model.to_string(),
        serial: String::new(),
        vid: desc.vendor_id(),
        pid: desc.product_id(),
        timestamp: timestamp.clone(),
        reports: all_reports,
    };

    let filename = output_dir.join(format!("usb_dump_{}.json", timestamp));
    let tmp = filename.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(&dump)?)?;
    fs::rename(&tmp, &filename)?;
    println!("\nSaved to: {}", filename.display());

    Ok(())
}

/// Deep probe: try all 3 report types (Input/Output/Feature) on all report IDs,
/// then try known DualSense command sequences to unlock profile data.
pub fn usb_probe() -> Result<(), Box<dyn std::error::Error>> {
    let devices = rusb::devices()?;
    let device = devices
        .iter()
        .find(|d| {
            let desc = d.device_descriptor().unwrap();
            desc.vendor_id() == SONY_VID
                && (desc.product_id() == DUALSENSE_EDGE_PID || desc.product_id() == DUALSENSE_PID)
        })
        .ok_or("No DualSense controller found")?;

    let mut handle = device.open()?;
    let iface: u16 = 3;

    // Try to claim interface
    handle.detach_kernel_driver(iface as u8).ok();
    let claimed = handle.claim_interface(iface as u8).is_ok();
    if !claimed {
        println!("{}", "Could not claim interface 3 — continuing anyway".yellow());
    }

    let request_type_in = USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE;
    let request_type_out = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE;

    // === Phase 1: Try all report types ===
    for (type_name, type_value) in [
        ("Input", HID_REPORT_TYPE_INPUT),
        ("Output", HID_REPORT_TYPE_OUTPUT),
        ("Feature", HID_REPORT_TYPE_FEATURE),
    ] {
        println!(
            "\n{}",
            format!("=== GET_REPORT type={} (0x{:04X}) ===", type_name, type_value)
                .cyan()
                .bold()
        );

        let mut found = 0u32;
        for report_id in 0x00..=0xFFu8 {
            let mut buf = vec![0u8; 1024];
            let value = type_value | report_id as u16;

            match handle.read_control(
                request_type_in,
                HID_GET_REPORT,
                value,
                iface,
                &mut buf,
                Duration::from_millis(200),
            ) {
                Ok(len) if len > 0 => {
                    found += 1;
                    println!(
                        "  {} 0x{:02X}: {} bytes",
                        type_name.green(),
                        report_id,
                        len
                    );
                    // Only print hex for reports > 4 bytes (skip trivial ones)
                    if len > 4 {
                        println!("{}", hex_dump(&buf[..len]));
                    } else {
                        print!("    ");
                        for b in &buf[..len] {
                            print!("{:02X} ", b);
                        }
                        println!();
                    }
                }
                _ => {}
            }
        }
        println!("  Total: {} reports", found);
    }

    // === Phase 2: Try known DualSense Edge command sequences ===
    println!(
        "\n{}",
        "=== Trying command/response sequences ===".cyan().bold()
    );

    // The DualSense USB output report is ID 0x02 (48 bytes)
    // Try sending various output reports and then reading responses

    // Command: Request profile data
    // Some known approaches from community RE:
    //   - SET_REPORT feature with specific payloads
    //   - Output report 0x02 with specific flag bytes

    // Try SET_REPORT feature with small probe payloads
    // These are exploratory — we try various report IDs with a minimal payload
    println!("\n  Trying SET_REPORT → GET_REPORT sequences...");

    for probe_id in [0x20u8, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
                     0x30, 0x31, 0x32, 0x40, 0x41, 0x42, 0x50, 0x60, 0x61, 0x62, 0x63,
                     0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
                     0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A,
                     0x90, 0x91, 0xA0, 0xA1, 0xA2, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xF1] {
        // Try: SET_REPORT feature with just the report ID + zeros
        let set_buf = vec![probe_id; 1]; // minimal payload
        let set_value = HID_REPORT_TYPE_FEATURE | probe_id as u16;

        let set_result = handle.write_control(
            request_type_out,
            HID_SET_REPORT,
            set_value,
            iface,
            &set_buf,
            Duration::from_millis(200),
        );

        if set_result.is_ok() {
            // Now try to read the response
            let mut resp = vec![0u8; 1024];
            resp[0] = probe_id;
            if let Ok(len) = handle.read_control(
                request_type_in,
                HID_GET_REPORT,
                set_value,
                iface,
                &mut resp,
                Duration::from_millis(200),
            ) {
                if len > 0 {
                    println!(
                        "  {} SET+GET 0x{:02X}: SET accepted, GET returned {} bytes",
                        "HIT".green().bold(),
                        probe_id,
                        len
                    );
                    println!("{}", hex_dump(&resp[..len]));
                }
            }
        }
    }

    // === Phase 3: Try reading interrupt endpoint directly ===
    // After sending various SET_REPORTs, check if the controller sends
    // data back on the interrupt IN endpoint (0x84)
    println!("\n  Reading interrupt endpoint for unsolicited responses...");
    let mut int_buf = [0u8; 256];
    for _ in 0..10 {
        match handle.read_interrupt(0x84, &mut int_buf, Duration::from_millis(100)) {
            Ok(len) if len > 0 => {
                println!(
                    "  {} Interrupt data: {} bytes (report ID: 0x{:02X})",
                    "GOT".green().bold(),
                    len,
                    int_buf[0]
                );
                if len > 20 {
                    println!("{}", hex_dump(&int_buf[..len]));
                }
            }
            _ => {}
        }
    }

    if claimed {
        handle.release_interface(iface as u8).ok();
    }
    handle.attach_kernel_driver(iface as u8).ok();

    println!(
        "\n{}",
        "Probe complete.".cyan()
    );
    Ok(())
}

/// Read Edge profile feature reports (0x60-0x7B) with detailed error reporting.
/// These are the reports that contain profile data (curves, deadzones, button mappings).
pub fn read_profiles(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let devices = rusb::devices()?;
    let device = devices
        .iter()
        .find(|d| {
            let desc = d.device_descriptor().unwrap();
            desc.vendor_id() == SONY_VID && desc.product_id() == DUALSENSE_EDGE_PID
        })
        .ok_or("No DualSense Edge found (this command is Edge-specific)")?;

    let handle = device.open()?;
    let iface: u8 = 3;

    // Detach kernel driver
    match handle.kernel_driver_active(iface) {
        Ok(true) => {
            println!("Detaching kernel driver from interface {}...", iface);
            handle.detach_kernel_driver(iface)?;
        }
        _ => {}
    }

    let claimed = handle.claim_interface(iface);
    println!(
        "Claim interface {}: {}",
        iface,
        if claimed.is_ok() {
            "OK".green().to_string()
        } else {
            format!("FAILED: {:?}", claimed.err().unwrap()).red().to_string()
        }
    );

    let request_type_in = USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE;

    // Collect all target report IDs
    let target_ids: Vec<u8> = EDGE_EXTRA_REPORTS
        .iter()
        .copied()
        .chain(EDGE_PROFILE_REPORTS)
        .collect();

    println!(
        "\n{}",
        "=== Reading Edge-specific feature reports ==="
            .cyan()
            .bold()
    );

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let mut all_reports = Vec::new();

    // Try multiple buffer sizes per report
    for &report_id in &target_ids {
        let mut found = false;

        for buf_size in [64, 128, 256, 512, 1024] {
            let mut buf = vec![0u8; buf_size];
            let value = HID_REPORT_TYPE_FEATURE | report_id as u16;

            match handle.read_control(
                request_type_in,
                HID_GET_REPORT,
                value,
                iface as u16,
                &mut buf,
                Duration::from_millis(1000),
            ) {
                Ok(len) if len > 0 => {
                    println!(
                        "  {} 0x{:02X}: {} bytes (buf_size={})",
                        "OK".green().bold(),
                        report_id,
                        len,
                        buf_size
                    );
                    println!("{}", hex_dump(&buf[..len]));
                    all_reports.push(FeatureReport {
                        report_id,
                        length: len,
                        data: buf[..len].to_vec(),
                        timestamp: chrono::Local::now().to_rfc3339(),
                    });
                    found = true;
                    break;
                }
                Ok(_) => {
                    println!(
                        "  {} 0x{:02X}: 0 bytes returned (buf_size={})",
                        "EMPTY".yellow(),
                        report_id,
                        buf_size
                    );
                }
                Err(e) => {
                    if buf_size == 64 {
                        // Only print error on first attempt
                        println!(
                            "  {} 0x{:02X}: {} (will try larger buffers)",
                            "ERR".red(),
                            report_id,
                            e
                        );
                    }
                }
            }
        }

        if !found {
            println!(
                "  {} 0x{:02X}: all buffer sizes failed",
                "FAIL".red().bold(),
                report_id
            );
        }
    }

    // Also try the standard 6 for reference
    println!(
        "\n{}",
        "=== Standard reports (reference) ===".cyan().bold()
    );
    for report_id in [0x05u8, 0x09, 0x0B, 0x85, 0xF2, 0xF5] {
        let mut buf = vec![0u8; 1024];
        let value = HID_REPORT_TYPE_FEATURE | report_id as u16;
        match handle.read_control(
            request_type_in,
            HID_GET_REPORT,
            value,
            iface as u16,
            &mut buf,
            Duration::from_millis(500),
        ) {
            Ok(len) if len > 0 => {
                println!("  0x{:02X}: {} bytes", report_id, len);
                all_reports.push(FeatureReport {
                    report_id,
                    length: len,
                    data: buf[..len].to_vec(),
                    timestamp: chrono::Local::now().to_rfc3339(),
                });
            }
            Ok(_) => println!("  0x{:02X}: empty", report_id),
            Err(e) => println!("  0x{:02X}: {}", report_id, e),
        }
    }

    // Save results
    if !all_reports.is_empty() {
        fs::create_dir_all(output_dir)?;
        let dump = DeviceDump {
            device_name: "DualSense Edge".to_string(),
            serial: String::new(),
            vid: SONY_VID,
            pid: DUALSENSE_EDGE_PID,
            timestamp: timestamp.clone(),
            reports: all_reports,
        };
        let path = output_dir.join(format!("edge_profiles_{}.json", timestamp));
        fs::write(&path, serde_json::to_string_pretty(&dump)?)?;
        println!("\nSaved to: {}", path.display());
    }

    handle.release_interface(iface).ok();
    handle.attach_kernel_driver(iface).ok();

    Ok(())
}

/// Write report ID mapping: profiles are WRITTEN via 0x60-0x63, not 0x70-0x7B.
/// Each write report accepts all 3 buffers (buffer index in byte[1]).
/// Confirmed from USB capture of PlayStation Accessories app on Windows:
///   0x60 = Profile 3  (reads from 0x73-0x75)  -- confirmed
///   0x61 = Profile 2  (reads from 0x76-0x78)  -- confirmed
///   0x62 = Profile 1  (reads from 0x79-0x7B)  -- confirmed
///   0x63 = Default     (reads from 0x70-0x72)
///
/// Indexed by read-slot: slot 0 (Default)=0x63, slot 1 (P3)=0x60, slot 2 (P2)=0x61, slot 3 (P1)=0x62
const EDGE_WRITE_REPORT_IDS: [u8; 4] = [0x63, 0x60, 0x61, 0x62];

/// Write 3 profile buffers via hidraw (kernel HID layer).
/// Uses the write-specific report IDs (0x60-0x63) discovered from USB capture.
pub fn write_profile_hidraw(
    slot: u8,
    buf0: &[u8; 64],
    buf1: &[u8; 64],
    buf2: &[u8; 64],
) -> Result<(), Box<dyn std::error::Error>> {
    if slot > 3 {
        return Err("Profile slot must be 0-3".into());
    }

    let path = find_edge_hidraw_path()?;
    let api = hidapi::HidApi::new()?;
    let device = api.open_path(std::ffi::CString::new(path.clone())?.as_ref())
        .map_err(|e| format!("Cannot open {}: {}", path, e))?;

    println!("Opened DualSense Edge via {}", path);

    // The write report ID for this slot
    let write_id = EDGE_WRITE_REPORT_IDS[slot as usize];
    println!("  Write report ID: 0x{:02X} (slot {})", write_id, slot);

    // Rewrite byte[0] of each buffer to the write report ID
    // All 3 buffers use the SAME report ID; byte[1] is the buffer index (0, 1, 2)
    let bufs: [(&[u8; 64], u8); 3] = [
        (buf0, 0), // buffer index 0
        (buf1, 1), // buffer index 1
        (buf2, 2), // buffer index 2
    ];

    for (buf, buf_idx) in &bufs {
        let mut write_buf = **buf;
        write_buf[0] = write_id;  // Override report ID to write endpoint
        write_buf[1] = *buf_idx;  // Ensure buffer index is correct

        match device.send_feature_report(&write_buf) {
            Ok(()) => {
                println!(
                    "  {} SET_FEATURE 0x{:02X} buf[{}]: 64 bytes",
                    "OK".green().bold(),
                    write_id,
                    buf_idx
                );
            }
            Err(e) => {
                return Err(format!(
                    "SET_FEATURE 0x{:02X} buf[{}] failed: {}",
                    write_id, buf_idx, e
                ).into());
            }
        }
    }

    // Read back from the READ report IDs to verify
    let read_base = 0x70 + slot * 3;
    println!("\n  Verifying via read reports 0x{:02X}-0x{:02X}...", read_base, read_base + 2);
    for buf_idx in 0..3u8 {
        let read_id = read_base + buf_idx;
        let mut readback = vec![0u8; 64];
        readback[0] = read_id;
        match device.get_feature_report(&mut readback) {
            Ok(len) if len == 64 => {
                // Compare data portion (skip byte 0 which is report ID, and byte 1 which may differ)
                let orig = match buf_idx {
                    0 => buf0,
                    1 => buf1,
                    _ => buf2,
                };
                // Compare bytes 2..60 (the meaningful data, excluding report ID and buffer index)
                if readback[2..60] == orig[2..60] {
                    println!(
                        "  {} 0x{:02X}: data verified",
                        "OK".green().bold(),
                        read_id,
                    );
                } else {
                    let diffs: Vec<usize> = readback[2..60]
                        .iter()
                        .zip(orig[2..60].iter())
                        .enumerate()
                        .filter(|(_, (a, b))| a != b)
                        .map(|(i, _)| i + 2)
                        .collect();
                    println!(
                        "  {} 0x{:02X}: {} byte(s) differ at {:?}",
                        "MISMATCH".yellow(),
                        read_id,
                        diffs.len(),
                        diffs
                    );
                }
            }
            Ok(len) => println!("  0x{:02X}: {} bytes (expected 64)", read_id, len),
            Err(e) => println!("  0x{:02X}: read-back failed: {}", read_id, e),
        }
    }

    Ok(())
}

/// Find the hidraw path for the DualSense Edge by scanning sysfs.
pub fn find_edge_hidraw_path() -> Result<String, Box<dyn std::error::Error>> {
    for entry in std::fs::read_dir("/sys/class/hidraw")? {
        let entry = entry?;
        let uevent_path = entry.path().join("device/uevent");
        if let Ok(contents) = std::fs::read_to_string(&uevent_path) {
            if contents.contains("054C") && contents.contains("0DF2") {
                let name = entry.file_name().to_string_lossy().to_string();
                return Ok(format!("/dev/{}", name));
            }
        }
    }
    Err("No DualSense Edge hidraw device found. Is the controller connected?".into())
}

/// Diagnostic: read a profile slot and try to write it back unchanged.
/// Tests whether SET_FEATURE works at all for these report IDs.
pub fn test_write() -> Result<(), Box<dyn std::error::Error>> {
    let path = find_edge_hidraw_path()?;
    println!("Found DualSense Edge at {}", path);

    let api = hidapi::HidApi::new()?;
    let device = api.open_path(std::ffi::CString::new(path.clone())?.as_ref())
        .map_err(|e| format!("Cannot open {}: {}", path, e))?;

    println!("Opened via hidraw");

    // Test 1: Read report 0x79 and echo it back
    let mut buf = vec![0u8; 64];
    buf[0] = 0x79;
    let len = device.get_feature_report(&mut buf)?;
    println!("\nGET_FEATURE 0x79: {} bytes", len);
    println!("{}", crate::reports::hex_dump(&buf[..len]));

    println!("\n--- Test: echo back 0x79 unchanged ---");
    match device.send_feature_report(&buf[..len]) {
        Ok(()) => println!("{}", "OK!".green().bold()),
        Err(e) => println!("{}", format!("FAILED: {}", e).red()),
    }

    // Test 2: Try a simple known writable report
    println!("\n--- Test: echo back 0x85 (4 bytes) ---");
    let mut small = vec![0u8; 4];
    small[0] = 0x85;
    let slen = device.get_feature_report(&mut small)?;
    println!("Read: {:02X?}", &small[..slen]);
    match device.send_feature_report(&small[..slen]) {
        Ok(()) => println!("{}", "OK!".green().bold()),
        Err(e) => println!("{}", format!("FAILED: {}", e).red()),
    }

    // Test 3: Try output report 0x02 (standard DualSense output)
    println!("\n--- Test: SET_FEATURE 0x05 (calibration, 41 bytes) ---");
    let mut cal = vec![0u8; 41];
    cal[0] = 0x05;
    let clen = device.get_feature_report(&mut cal)?;
    println!("Read: {} bytes", clen);
    match device.send_feature_report(&cal[..clen]) {
        Ok(()) => println!("{}", "OK!".green().bold()),
        Err(e) => println!("{}", format!("FAILED: {}", e).red()),
    }

    drop(device);
    drop(api);

    // Test 0x80 command interface (used for calibration unlock/lock)
    println!("\n--- Test: SET_FEATURE 0x80 (command interface) ---");
    {
        let api2 = hidapi::HidApi::new()?;
        let path2 = find_edge_hidraw_path()?;
        let dev2 = api2.open_path(std::ffi::CString::new(path2)?.as_ref())
            .map_err(|e| format!("Cannot reopen: {}", e))?;

        // Try NVS unlock: [3, 2, 101, 50, 64, 12]
        let mut cmd = vec![0u8; 64];
        cmd[0] = 0x80; // report ID
        cmd[1] = 3; cmd[2] = 2; cmd[3] = 101; cmd[4] = 50; cmd[5] = 64; cmd[6] = 12;
        println!("  Sending NVS unlock [3,2,101,50,64,12] via 0x80...");
        match dev2.send_feature_report(&cmd) {
            Ok(()) => {
                println!("{}", "  NVS unlock accepted!".green().bold());

                // Read response from 0x81
                std::thread::sleep(Duration::from_millis(200));
                let mut resp = vec![0u8; 64];
                resp[0] = 0x81;
                match dev2.get_feature_report(&mut resp) {
                    Ok(rlen) => {
                        println!("  Response 0x81: {} bytes", rlen);
                        println!("{}", crate::reports::hex_dump(&resp[..rlen]));
                    }
                    Err(e) => println!("  No 0x81 response: {}", e),
                }

                // Now try writing a profile report
                println!("\n  NVS unlocked — retrying SET_FEATURE 0x79...");
                match dev2.send_feature_report(&buf[..len]) {
                    Ok(()) => println!("{}", "  SET_FEATURE 0x79 OK!".green().bold()),
                    Err(e) => println!("  Still failed: {}", format!("{}", e).red()),
                }

                // Try NVS lock after
                let mut lock_cmd = vec![0u8; 64];
                lock_cmd[0] = 0x80;
                lock_cmd[1] = 3; lock_cmd[2] = 1;
                let _ = dev2.send_feature_report(&lock_cmd);
            }
            Err(e) => println!("  0x80 also rejected: {}", format!("{}", e).red()),
        }
    }

    // Probe 0x80 command space for profile-related commands
    println!("\n--- Probing 0x80 command space ---");
    {
        let api3 = hidapi::HidApi::new()?;
        let path3 = find_edge_hidraw_path()?;
        let dev3 = api3.open_path(std::ffi::CString::new(path3)?.as_ref())
            .map_err(|e| format!("Cannot reopen: {}", e))?;

        // Known 0x80 commands from RE:
        // [3,1] = NVS lock, [3,2,101,50,64,12] = NVS unlock, [3,3] = NVS status
        // [9,2] = get BT addr, [12,1,...] = write finetune, [12,2] = read cal, [12,4] = read cal (Edge)
        // [21,...] = module unlock/lock/barcode
        // Let's try probing for profile-related commands
        let probes: Vec<(Vec<u8>, &str)> = vec![
            // Query-style commands (read profile via command interface?)
            (vec![0x10, 0x01], "0x10,0x01"),
            (vec![0x10, 0x02], "0x10,0x02"),
            (vec![0x10, 0x03], "0x10,0x03"),
            (vec![0x10, 0x04], "0x10,0x04"),
            (vec![0x11, 0x01], "0x11,0x01"),
            (vec![0x11, 0x02], "0x11,0x02"),
            (vec![0x13, 0x01], "0x13,0x01"),
            (vec![0x13, 0x02], "0x13,0x02"),
            (vec![0x14, 0x01], "0x14,0x01"),
            (vec![0x14, 0x02], "0x14,0x02"),
            (vec![0x15, 0x01], "0x15,0x01"),
            (vec![0x15, 0x02], "0x15,0x02"),
            // Profile-related?
            (vec![0x20, 0x01], "0x20,0x01"),
            (vec![0x20, 0x02], "0x20,0x02"),
            (vec![0x30, 0x01], "0x30,0x01"),
            (vec![0x30, 0x02], "0x30,0x02"),
            // NVS status
            (vec![0x03, 0x03], "NVS status"),
            // Read calibration (Edge)
            (vec![0x0C, 0x04], "read cal Edge"),
            // System info
            (vec![0x09, 0x02], "BT addr"),
            (vec![0x20, 0x02, 0x00], "0x20,0x02,0x00 (fw info?)"),
        ];

        for (cmd_data, label) in &probes {
            let mut cmd = vec![0u8; 64];
            cmd[0] = 0x80;
            for (i, &b) in cmd_data.iter().enumerate() {
                cmd[i + 1] = b;
            }

            match dev3.send_feature_report(&cmd) {
                Ok(()) => {
                    std::thread::sleep(Duration::from_millis(50));
                    let mut resp = vec![0u8; 64];
                    resp[0] = 0x81;
                    match dev3.get_feature_report(&mut resp) {
                        Ok(rlen) => {
                            // Check if response is non-empty (not all zeros after report ID)
                            let has_data = resp[1..rlen].iter().any(|&b| b != 0);
                            if has_data {
                                println!(
                                    "  {} cmd [{}]: response {} bytes",
                                    "HIT".green().bold(),
                                    label,
                                    rlen
                                );
                                println!("{}", crate::reports::hex_dump(&resp[..rlen.min(64)]));
                            } else {
                                println!("  cmd [{}]: accepted, empty response", label);
                            }
                        }
                        Err(_) => println!("  cmd [{}]: accepted, no 0x81 response", label),
                    }
                }
                Err(e) => {
                    // Only print if it's not a pipe error (which means rejected)
                    if !e.to_string().contains("Broken pipe") {
                        println!("  cmd [{}]: {}", label, e);
                    }
                }
            }
        }

        // NVS lock to clean up
        let mut lock = vec![0u8; 64];
        lock[0] = 0x80; lock[1] = 3; lock[2] = 1;
        let _ = dev3.send_feature_report(&lock);
    }

    // Test via raw USB: detach driver, claim, read, then write back
    println!("\n--- Test: raw USB (detach driver, claim, read+write) ---");
    let devices = rusb::devices()?;
    let usb_dev = devices
        .iter()
        .find(|d| {
            let desc = d.device_descriptor().unwrap();
            desc.vendor_id() == SONY_VID && desc.product_id() == DUALSENSE_EDGE_PID
        })
        .ok_or("No device")?;

    let handle = usb_dev.open()?;
    let iface: u8 = 3;

    println!("  Detaching kernel driver...");
    handle.detach_kernel_driver(iface).ok();
    println!("  Claiming interface 3...");
    handle.claim_interface(iface)?;

    let req_in = USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE;
    let req_out = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE;

    // Read 0x79 via raw USB to verify connection
    let mut rbuf = vec![0u8; 64];
    let value_79 = HID_REPORT_TYPE_FEATURE | 0x79u16;
    let rlen = handle.read_control(req_in, HID_GET_REPORT, value_79, iface as u16, &mut rbuf, Duration::from_millis(1000))?;
    println!("  GET_REPORT 0x79: {} bytes - {}", rlen, "OK".green());

    // Now try writing it back — test all payload variations
    for (label, data) in [
        ("64B with ID", rbuf[..rlen].to_vec()),
        ("63B no ID", rbuf[1..rlen].to_vec()),
        ("64B with write CRC", {
            let mut d = rbuf[..64].to_vec();
            d[60..64].fill(0);
            let crc = {
                use crc::{Crc, CRC_32_ISO_HDLC};
                let algo = Crc::<u32>::new(&CRC_32_ISO_HDLC);
                let mut dig = algo.digest();
                dig.update(&[0xA3]);
                dig.update(&d);
                dig.finalize()
            };
            d[60..64].copy_from_slice(&crc.to_le_bytes());
            d
        }),
        ("63B no ID with write CRC", {
            let mut d = rbuf[..64].to_vec();
            d[60..64].fill(0);
            let crc = {
                use crc::{Crc, CRC_32_ISO_HDLC};
                let algo = Crc::<u32>::new(&CRC_32_ISO_HDLC);
                let mut dig = algo.digest();
                dig.update(&[0xA3]);
                dig.update(&d);
                dig.finalize()
            };
            d[60..64].copy_from_slice(&crc.to_le_bytes());
            d[1..].to_vec()
        }),
    ] {
        match handle.write_control(req_out, HID_SET_REPORT, value_79, iface as u16, &data, Duration::from_millis(1000)) {
            Ok(w) => println!("  SET_REPORT {}: {} bytes - {}", label, w, "OK".green().bold()),
            Err(e) => println!("  SET_REPORT {}: {}", label, format!("{}", e).red()),
        }
    }

    // Also test a smaller report
    println!("\n  Testing SET_REPORT on 0x85 (4 bytes)...");
    let value_85 = HID_REPORT_TYPE_FEATURE | 0x85u16;
    let mut sbuf = vec![0u8; 64];
    if let Ok(slen) = handle.read_control(req_in, HID_GET_REPORT, value_85, iface as u16, &mut sbuf, Duration::from_millis(500)) {
        println!("  GET_REPORT 0x85: {} bytes {:02X?}", slen, &sbuf[..slen]);
        match handle.write_control(req_out, HID_SET_REPORT, value_85, iface as u16, &sbuf[..slen], Duration::from_millis(500)) {
            Ok(w) => println!("  SET_REPORT 0x85: {} bytes - {}", w, "OK".green().bold()),
            Err(e) => println!("  SET_REPORT 0x85: {}", format!("{}", e).red()),
        }
    }

    handle.release_interface(iface).ok();
    println!("\n  Reattaching kernel driver...");
    handle.attach_kernel_driver(iface).ok();

    Ok(())
}

/// Write 3 profile buffers to a specific slot via SET_REPORT feature.
/// slot: 0-3 (maps to report IDs 0x70-0x7B)
pub fn write_profile(
    slot: u8,
    buf0: &[u8; 64],
    buf1: &[u8; 64],
    buf2: &[u8; 64],
) -> Result<(), Box<dyn std::error::Error>> {
    if slot > 3 {
        return Err("Profile slot must be 0-3".into());
    }

    let devices = rusb::devices()?;
    let device = devices
        .iter()
        .find(|d| {
            let desc = d.device_descriptor().unwrap();
            desc.vendor_id() == SONY_VID && desc.product_id() == DUALSENSE_EDGE_PID
        })
        .ok_or("No DualSense Edge found")?;

    let handle = device.open()?;
    let iface: u8 = 3;

    match handle.kernel_driver_active(iface) {
        Ok(true) => {
            println!("Detaching kernel driver...");
            handle.detach_kernel_driver(iface)?;
        }
        _ => {}
    }

    handle.claim_interface(iface)?;

    let request_type_out = USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE;
    let base_id = 0x70 + slot * 3;

    let buffers: [(&[u8; 64], u8); 3] = [
        (buf0, base_id),
        (buf1, base_id + 1),
        (buf2, base_id + 2),
    ];

    for (buf, report_id) in &buffers {
        let value = HID_REPORT_TYPE_FEATURE | *report_id as u16;

        // SET_REPORT: the report ID is in wValue, so send data WITHOUT the
        // report ID prefix. The device expects 63 bytes (buf[1..64]).
        // If that fails, retry with all 64 bytes (some devices want the ID included).
        let result = handle.write_control(
            request_type_out,
            HID_SET_REPORT,
            value,
            iface as u16,
            &buf[1..],  // 63 bytes, no report ID
            Duration::from_millis(1000),
        );

        let written = match result {
            Ok(w) => w,
            Err(_) => {
                // Retry with report ID included (64 bytes)
                handle.write_control(
                    request_type_out,
                    HID_SET_REPORT,
                    value,
                    iface as u16,
                    buf.as_slice(),
                    Duration::from_millis(1000),
                )?
            }
        };

        println!(
            "  {} SET_REPORT 0x{:02X}: {} bytes written",
            "OK".green().bold(),
            report_id,
            written
        );
    }

    // Read back to verify
    println!("\n  Verifying...");
    let request_type_in = USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE;
    for (expected, report_id) in &buffers {
        let mut readback = vec![0u8; 64];
        let value = HID_REPORT_TYPE_FEATURE | *report_id as u16;
        match handle.read_control(
            request_type_in,
            HID_GET_REPORT,
            value,
            iface as u16,
            &mut readback,
            Duration::from_millis(1000),
        ) {
            Ok(64) => {
                if readback == expected.as_slice() {
                    println!(
                        "  {} 0x{:02X}: verified",
                        "OK".green().bold(),
                        report_id
                    );
                } else {
                    let diffs: Vec<usize> = readback
                        .iter()
                        .zip(expected.iter())
                        .enumerate()
                        .filter(|(_, (a, b))| a != b)
                        .map(|(i, _)| i)
                        .collect();
                    println!(
                        "  {} 0x{:02X}: {} byte(s) differ at offsets {:?}",
                        "MISMATCH".red().bold(),
                        report_id,
                        diffs.len(),
                        diffs
                    );
                }
            }
            Ok(len) => println!(
                "  {} 0x{:02X}: unexpected size {} (expected 64)",
                "WARN".yellow(),
                report_id,
                len
            ),
            Err(e) => println!(
                "  {} 0x{:02X}: read-back failed: {}",
                "ERR".red(),
                report_id,
                e
            ),
        }
    }

    handle.release_interface(iface).ok();
    handle.attach_kernel_driver(iface).ok();

    Ok(())
}
