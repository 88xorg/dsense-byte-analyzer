use crate::hid;
use crate::reports::InputReport;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub fn run(log_path: Option<&Path>) -> Result<(), Box<dyn std::error::Error>> {
    let api = hidapi::HidApi::new()?;
    let (device, info) = hid::open_device(&api)?;

    let model = if info.is_edge {
        "DualSense Edge"
    } else {
        "DualSense"
    };
    println!("Monitoring {} (serial: {})", model, info.serial);
    println!("Press Ctrl+C to stop.\n");

    // Set up Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    // Set non-blocking so we can check the running flag
    device.set_blocking_mode(false)?;

    let mut log_file = log_path.map(|p| {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .expect("Failed to open log file")
    });

    let mut buf = [0u8; 128];
    let mut frame = 0u64;

    while running.load(Ordering::SeqCst) {
        match device.read(&mut buf) {
            Ok(0) => {
                // No data available (non-blocking)
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            Ok(len) => {
                frame += 1;

                if let Some(report) = InputReport::from_usb_bytes(&buf[..len]) {
                    // Overwrite the current line for live display
                    print!("\r[{:8}] {}", frame, report);
                    std::io::stdout().flush()?;
                }

                // Log raw bytes if requested
                if let Some(ref mut f) = log_file {
                    let ts = chrono::Local::now().to_rfc3339();
                    write!(f, "{} ", ts)?;
                    for b in &buf[..len] {
                        write!(f, "{:02X}", b)?;
                    }
                    writeln!(f)?;
                }
            }
            Err(e) => {
                // hidapi returns an error on timeout with non-blocking, which is normal
                let msg = e.to_string();
                if msg.is_empty() || msg.contains("No data") {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                return Err(e.into());
            }
        }
    }

    println!("\n\nStopped. {} frames read.", frame);
    Ok(())
}
