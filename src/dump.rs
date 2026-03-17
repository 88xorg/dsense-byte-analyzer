use crate::hid;
use crate::reports::{hex_dump, DeviceDump, FeatureReport};
use colored::Colorize;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

/// Dump all feature reports from the controller to a JSON file
pub fn dump_reports(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let api = hidapi::HidApi::new()?;
    let (device, info) = hid::open_device(&api)?;

    let model = if info.is_edge { "DualSense Edge" } else { "DualSense" };
    println!("Connected to {} (serial: {})", model, info.serial);
    println!("Dumping feature reports 0x00..0xFF...\n");

    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let mut reports = Vec::new();
    let mut success_count = 0;
    let mut error_count = 0;

    for report_id in 0x00..=0xFFu8 {
        // Start with 256 byte buffer; if full, retry with larger
        let mut buf_size = 256;
        loop {
            let mut buf = vec![0u8; buf_size];
            buf[0] = report_id;

            match device.get_feature_report(&mut buf) {
                Ok(len) => {
                    success_count += 1;
                    println!(
                        "Report 0x{:02X}: {} bytes {}",
                        report_id,
                        len,
                        "OK".green()
                    );
                    println!("{}", hex_dump(&buf[..len]));

                    reports.push(FeatureReport {
                        report_id,
                        length: len,
                        data: buf[..len].to_vec(),
                        timestamp: chrono::Local::now().to_rfc3339(),
                    });

                    // If we got exactly buf_size bytes, the report might be truncated
                    if len == buf_size && buf_size < 4096 {
                        buf_size *= 2;
                        continue;
                    }
                    break;
                }
                Err(_) => {
                    error_count += 1;
                    break;
                }
            }
        }
    }

    println!(
        "\nDump complete: {} reports read, {} failed/unsupported",
        success_count, error_count
    );

    // Save JSON dump
    let dump = DeviceDump {
        device_name: info.product.clone(),
        serial: info.serial.clone(),
        vid: info.vid,
        pid: info.pid,
        timestamp: timestamp.clone(),
        reports,
    };

    fs::create_dir_all(output_dir)?;
    let filename = output_dir.join(format!("dump_{}.json", timestamp));
    let tmp_filename = filename.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(&dump)?;
    fs::write(&tmp_filename, &json)?;
    fs::rename(&tmp_filename, &filename)?;

    println!("Saved to: {}", filename.display());
    Ok(())
}

/// Diff two dump files and show byte-level changes
pub fn diff_dumps(path_a: &Path, path_b: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let dump_a: DeviceDump = serde_json::from_str(&fs::read_to_string(path_a)?)?;
    let dump_b: DeviceDump = serde_json::from_str(&fs::read_to_string(path_b)?)?;

    println!(
        "Comparing:\n  A: {} ({})\n  B: {} ({})\n",
        path_a.display(),
        dump_a.timestamp,
        path_b.display(),
        dump_b.timestamp,
    );

    let map_a: HashMap<u8, &FeatureReport> =
        dump_a.reports.iter().map(|r| (r.report_id, r)).collect();
    let map_b: HashMap<u8, &FeatureReport> =
        dump_b.reports.iter().map(|r| (r.report_id, r)).collect();

    let mut changed_reports = 0;
    let mut total_changed_bytes = 0;

    // Check all report IDs from both dumps
    let mut all_ids: Vec<u8> = map_a.keys().chain(map_b.keys()).copied().collect();
    all_ids.sort();
    all_ids.dedup();

    for &id in &all_ids {
        match (map_a.get(&id), map_b.get(&id)) {
            (Some(a), Some(b)) => {
                let max_len = a.data.len().max(b.data.len());
                let mut diffs = Vec::new();

                for i in 0..max_len {
                    let va = a.data.get(i).copied();
                    let vb = b.data.get(i).copied();
                    if va != vb {
                        diffs.push((i, va, vb));
                    }
                }

                if !diffs.is_empty() {
                    changed_reports += 1;
                    total_changed_bytes += diffs.len();

                    println!(
                        "{}",
                        format!(
                            "Report 0x{:02X}: {} byte(s) changed (A: {} bytes, B: {} bytes)",
                            id,
                            diffs.len(),
                            a.data.len(),
                            b.data.len()
                        )
                        .yellow()
                        .bold()
                    );

                    for (offset, va, vb) in &diffs {
                        let old_str = va
                            .map(|v| format!("0x{:02X}", v))
                            .unwrap_or_else(|| "---".to_string());
                        let new_str = vb
                            .map(|v| format!("0x{:02X}", v))
                            .unwrap_or_else(|| "---".to_string());
                        println!(
                            "  Offset {:4} (0x{:04X}): {} → {}",
                            offset,
                            offset,
                            old_str.red(),
                            new_str.green()
                        );
                    }
                    println!();
                }
            }
            (Some(_), None) => {
                println!(
                    "{}",
                    format!("Report 0x{:02X}: present in A only", id).red()
                );
            }
            (None, Some(_)) => {
                println!(
                    "{}",
                    format!("Report 0x{:02X}: present in B only", id).green()
                );
            }
            (None, None) => unreachable!(),
        }
    }

    if changed_reports == 0 {
        println!("{}", "No differences found between dumps.".cyan());
    } else {
        println!(
            "{}",
            format!(
                "Summary: {} report(s) changed, {} total byte(s) modified",
                changed_reports, total_changed_bytes
            )
            .yellow()
            .bold()
        );
    }

    Ok(())
}

/// Interactive capture session: take dumps with user-guided setting changes
pub fn capture_session(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Do an initial open just to verify connectivity and get device info
    let api = hidapi::HidApi::new()?;
    let (_device, info) = hid::open_device(&api)?;
    drop(_device);
    drop(api);

    let model = if info.is_edge { "DualSense Edge" } else { "DualSense" };
    println!("Connected to {} (serial: {})", model, info.serial);
    println!("Starting interactive capture session.\n");

    fs::create_dir_all(output_dir)?;

    // Take baseline
    println!("{}", "=== BASELINE CAPTURE ===".cyan().bold());
    println!("Set controller to Profile 1, all default settings.");
    wait_for_enter();

    let baseline = fresh_dump(&info)?;
    let baseline_path = output_dir.join("baseline.json");
    save_dump(&baseline, &baseline_path)?;
    println!("Baseline saved: {}\n", baseline_path.display());

    // Iterative captures
    let mut capture_num = 1;
    loop {
        println!(
            "{}",
            format!("=== CAPTURE #{} ===", capture_num).cyan().bold()
        );
        println!("Change ONE setting on the controller, then press Enter.");
        println!("(Or type 'q' to quit the session)");
        print!("> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim().eq_ignore_ascii_case("q") {
            break;
        }

        print!("Label for this capture (e.g., 'left_stick_quick_curve'): ");
        io::stdout().flush()?;
        let mut label = String::new();
        io::stdin().read_line(&mut label)?;
        let label = label.trim().replace(' ', "_");
        let label = if label.is_empty() {
            format!("capture_{}", capture_num)
        } else {
            label
        };

        let modified = fresh_dump(&info)?;
        let modified_path = output_dir.join(format!("{}.json", label));
        save_dump(&modified, &modified_path)?;
        println!("Saved: {}", modified_path.display());

        // Auto-diff against baseline
        println!("\n{}", "--- Diff vs. baseline ---".yellow().bold());
        diff_dump_structs(&baseline, &modified);
        println!();

        capture_num += 1;
    }

    println!("Session complete. {} capture(s) taken.", capture_num - 1);
    Ok(())
}

/// Open a fresh HID connection, take a dump, then close it.
/// macOS IOHIDManager can lose access to feature reports if the handle is kept open
/// too long or across user interaction pauses.
fn fresh_dump(info: &hid::DeviceInfo) -> Result<DeviceDump, Box<dyn std::error::Error>> {
    let api = hidapi::HidApi::new()?;
    let (device, _) = hid::open_device(&api)?;
    let result = take_dump(&device, info)?;
    drop(device);
    drop(api);
    Ok(result)
}

fn wait_for_enter() {
    print!("Press Enter when ready...");
    io::stdout().flush().unwrap();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
}

fn take_dump(
    device: &hidapi::HidDevice,
    info: &hid::DeviceInfo,
) -> Result<DeviceDump, Box<dyn std::error::Error>> {
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
    let mut reports = Vec::new();
    let mut success = 0u32;
    let mut fail = 0u32;

    for report_id in 0x00..=0xFFu8 {
        print!(
            "\r  Scanning report IDs... 0x{:02X}/0xFF ({} found, {} failed)",
            report_id, success, fail
        );
        io::stdout().flush()?;

        let mut buf_size = 256;
        loop {
            let mut buf = vec![0u8; buf_size];
            buf[0] = report_id;

            match device.get_feature_report(&mut buf) {
                Ok(len) => {
                    success += 1;
                    reports.push(FeatureReport {
                        report_id,
                        length: len,
                        data: buf[..len].to_vec(),
                        timestamp: chrono::Local::now().to_rfc3339(),
                    });
                    if len == buf_size && buf_size < 4096 {
                        buf_size *= 2;
                        continue;
                    }
                    break;
                }
                Err(_) => {
                    fail += 1;
                    break;
                }
            }
        }
    }

    println!(
        "\r  Dumped {} feature reports ({} IDs unsupported).       ",
        reports.len(),
        fail
    );

    Ok(DeviceDump {
        device_name: info.product.clone(),
        serial: info.serial.clone(),
        vid: info.vid,
        pid: info.pid,
        timestamp,
        reports,
    })
}

fn save_dump(dump: &DeviceDump, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(dump)?;
    fs::write(&tmp, &json)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn diff_dump_structs(a: &DeviceDump, b: &DeviceDump) {
    let map_a: HashMap<u8, &FeatureReport> = a.reports.iter().map(|r| (r.report_id, r)).collect();
    let map_b: HashMap<u8, &FeatureReport> = b.reports.iter().map(|r| (r.report_id, r)).collect();

    let mut any_diff = false;

    let mut all_ids: Vec<u8> = map_a.keys().chain(map_b.keys()).copied().collect();
    all_ids.sort();
    all_ids.dedup();

    for &id in &all_ids {
        if let (Some(ra), Some(rb)) = (map_a.get(&id), map_b.get(&id)) {
            let max_len = ra.data.len().max(rb.data.len());
            let mut diffs = Vec::new();
            for i in 0..max_len {
                let va = ra.data.get(i).copied();
                let vb = rb.data.get(i).copied();
                if va != vb {
                    diffs.push((i, va, vb));
                }
            }
            if !diffs.is_empty() {
                any_diff = true;
                println!(
                    "{}",
                    format!("Report 0x{:02X}: {} byte(s) changed", id, diffs.len())
                        .yellow()
                        .bold()
                );
                for (offset, va, vb) in &diffs {
                    let old_str = va
                        .map(|v| format!("0x{:02X}", v))
                        .unwrap_or_else(|| "---".into());
                    let new_str = vb
                        .map(|v| format!("0x{:02X}", v))
                        .unwrap_or_else(|| "---".into());
                    println!(
                        "  Offset {:4} (0x{:04X}): {} → {}",
                        offset,
                        offset,
                        old_str.red(),
                        new_str.green()
                    );
                }
            }
        }
    }

    if !any_diff {
        println!("{}", "No differences found.".cyan());
    }
}
