//! Capture full raw input reports and diff them.
//! The DualSense input report is ~64 bytes on USB. Profile state
//! may be encoded in bytes beyond the stick/button region.

use crate::hid;
use crate::reports::hex_dump;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputSnapshot {
    pub label: String,
    pub timestamp: String,
    pub report_len: usize,
    pub data: Vec<u8>,
    /// Multiple samples to identify volatile vs stable bytes
    pub samples: Vec<Vec<u8>>,
}

/// Capture multiple input report samples to identify stable vs volatile bytes
fn capture_samples(count: usize) -> Result<InputSnapshot, Box<dyn std::error::Error>> {
    let api = hidapi::HidApi::new()?;
    let (device, _info) = hid::open_device(&api)?;
    device.set_blocking_mode(true)?;

    let mut samples = Vec::new();
    let mut buf = [0u8; 256];

    // Read a few frames to let things settle, then capture
    for _ in 0..5 {
        device.read_timeout(&mut buf, 100)?;
    }

    for _ in 0..count {
        let len = device.read_timeout(&mut buf, 1000)?;
        if len > 0 {
            samples.push(buf[..len].to_vec());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    let data = samples.first().cloned().unwrap_or_default();
    let report_len = data.len();

    Ok(InputSnapshot {
        label: String::new(),
        timestamp: chrono::Local::now().to_rfc3339(),
        report_len,
        data,
        samples,
    })
}

/// Take two snapshots (before/after a setting change) and diff the full input reports
pub fn snapshot_session(output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    println!("{}", "=== Input Report Snapshot Session ===".cyan().bold());
    println!("This captures the FULL input report (~64 bytes) and diffs it.");
    println!("Stable bytes that change between profiles = profile indicators.\n");

    // Baseline
    println!("Set controller to Profile 1, all defaults.");
    println!("Leave the sticks centered and don't touch any buttons.");
    wait_for_enter();

    print!("Capturing baseline (20 samples)...");
    io::stdout().flush()?;
    let mut baseline = capture_samples(20)?;
    baseline.label = "baseline".to_string();
    println!(" done ({} bytes per report)", baseline.report_len);

    println!("\n{}", "Full input report:".yellow());
    println!("{}", hex_dump(&baseline.data));

    // Identify volatile bytes (change between samples even with no input change)
    let volatile = find_volatile_bytes(&baseline.samples);
    if !volatile.is_empty() {
        println!(
            "Volatile bytes (change between reads, ignore in diffs): {:?}",
            volatile.iter().map(|b| format!("0x{:02X}", b)).collect::<Vec<_>>()
        );
    }

    let baseline_path = output_dir.join("input_baseline.json");
    save_snapshot(&baseline, &baseline_path)?;
    println!("Saved: {}\n", baseline_path.display());

    // Iterative captures
    let mut capture_num = 1;
    loop {
        println!(
            "{}",
            format!("=== CAPTURE #{} ===", capture_num).cyan().bold()
        );
        println!("Change ONE profile setting, leave sticks centered, press Enter.");
        println!("(Or type 'q' to quit)");
        print!("> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim().eq_ignore_ascii_case("q") {
            break;
        }

        print!("Label: ");
        io::stdout().flush()?;
        let mut label = String::new();
        io::stdin().read_line(&mut label)?;
        let label = label.trim().replace(' ', "_");
        let label = if label.is_empty() {
            format!("capture_{}", capture_num)
        } else {
            label
        };

        print!("Capturing...");
        io::stdout().flush()?;
        let mut modified = capture_samples(20)?;
        modified.label = label.clone();
        println!(" done");

        // Diff against baseline, excluding volatile bytes
        println!("\n{}", "--- Diff vs. baseline ---".yellow().bold());
        diff_snapshots(&baseline, &modified, &volatile);

        let path = output_dir.join(format!("input_{}.json", label));
        save_snapshot(&modified, &path)?;
        println!("Saved: {}\n", path.display());

        capture_num += 1;
    }

    Ok(())
}

/// Find byte offsets that change between samples (volatile/noisy bytes)
fn find_volatile_bytes(samples: &[Vec<u8>]) -> Vec<usize> {
    if samples.len() < 2 {
        return vec![];
    }

    let len = samples[0].len();
    let mut volatile = Vec::new();

    for offset in 0..len {
        let first = samples[0].get(offset);
        for sample in &samples[1..] {
            if sample.get(offset) != first {
                volatile.push(offset);
                break;
            }
        }
    }

    volatile
}

fn diff_snapshots(a: &InputSnapshot, b: &InputSnapshot, volatile: &[usize]) {
    let max_len = a.data.len().max(b.data.len());
    let mut stable_diffs = Vec::new();
    let mut volatile_diffs = 0;

    for i in 0..max_len {
        let va = a.data.get(i).copied();
        let vb = b.data.get(i).copied();
        if va != vb {
            if volatile.contains(&i) {
                volatile_diffs += 1;
            } else {
                stable_diffs.push((i, va, vb));
            }
        }
    }

    if stable_diffs.is_empty() {
        println!(
            "{}",
            "No stable byte differences found.".red().bold()
        );
    } else {
        println!(
            "{}",
            format!("{} STABLE byte(s) changed (profile data!):", stable_diffs.len())
                .green()
                .bold()
        );
        for (offset, va, vb) in &stable_diffs {
            let old_str = va
                .map(|v| format!("0x{:02X} ({:3})", v, v))
                .unwrap_or_else(|| "---".into());
            let new_str = vb
                .map(|v| format!("0x{:02X} ({:3})", v, v))
                .unwrap_or_else(|| "---".into());
            println!(
                "  Byte {:3} (0x{:02X}): {} → {}",
                offset,
                offset,
                old_str.red(),
                new_str.green()
            );
        }
    }

    if volatile_diffs > 0 {
        println!(
            "  ({} volatile bytes also changed — ignored)",
            volatile_diffs
        );
    }

    // Show full hex side by side for context
    println!("\n  Baseline report:");
    println!("{}", hex_dump(&a.data));
    println!("  Modified report:");
    println!("{}", hex_dump(&b.data));
}

fn save_snapshot(snap: &InputSnapshot, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_string_pretty(snap)?)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn wait_for_enter() {
    print!("Press Enter when ready...");
    io::stdout().flush().unwrap();
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).unwrap();
}
