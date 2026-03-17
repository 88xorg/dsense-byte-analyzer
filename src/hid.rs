use crate::reports::{DUALSENSE_EDGE_PID, DUALSENSE_PID, SONY_VID};
use hidapi::{HidApi, HidDevice};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HidError {
    #[error("HID API error: {0}")]
    Api(#[from] hidapi::HidError),

    #[error("No DualSense controller found. Make sure it's connected via USB.")]
    NotFound,

    #[error(
        "Failed to open device. On macOS, grant Input Monitoring permission:\n  \
         System Settings → Privacy & Security → Input Monitoring\n  \
         Add your terminal app (Terminal.app, iTerm2, etc.) to the list."
    )]
    PermissionDenied,
}

pub type Result<T> = std::result::Result<T, HidError>;

/// Information about a discovered DualSense device
pub struct DeviceInfo {
    pub path: String,
    pub vid: u16,
    pub pid: u16,
    pub interface: i32,
    pub usage_page: u16,
    pub usage: u16,
    pub manufacturer: String,
    pub product: String,
    pub serial: String,
    pub is_edge: bool,
}

/// Discover and list all connected DualSense controllers
pub fn discover() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let api = HidApi::new()?;

    let mut found = Vec::new();

    for device in api.device_list() {
        let vid = device.vendor_id();
        let pid = device.product_id();

        if vid != SONY_VID || (pid != DUALSENSE_EDGE_PID && pid != DUALSENSE_PID) {
            continue;
        }

        let is_edge = pid == DUALSENSE_EDGE_PID;
        let model = if is_edge { "DualSense Edge" } else { "DualSense" };

        found.push(DeviceInfo {
            path: device.path().to_string_lossy().into_owned(),
            vid,
            pid,
            interface: device.interface_number(),
            usage_page: device.usage_page(),
            usage: device.usage(),
            manufacturer: device
                .manufacturer_string()
                .unwrap_or_default()
                .to_string(),
            product: device.product_string().unwrap_or_default().to_string(),
            serial: device.serial_number().unwrap_or_default().to_string(),
            is_edge,
        });

        println!("Found {} controller:", model);
        println!("  Path:         {}", device.path().to_string_lossy());
        println!("  VID:PID:      {:04X}:{:04X}", vid, pid);
        println!("  Interface:    {}", device.interface_number());
        println!("  Usage Page:   0x{:04X}", device.usage_page());
        println!("  Usage:        0x{:04X}", device.usage());
        println!(
            "  Manufacturer: {}",
            device.manufacturer_string().unwrap_or_default()
        );
        println!(
            "  Product:      {}",
            device.product_string().unwrap_or_default()
        );
        println!(
            "  Serial:       {}",
            device.serial_number().unwrap_or_default()
        );
        println!();
    }

    if found.is_empty() {
        eprintln!("No DualSense controllers found.");
        eprintln!("Make sure the controller is connected via USB cable.");
        eprintln!("Note: Bluetooth connection is not recommended for RE work.");
    } else {
        println!("Found {} interface(s) total.", found.len());
        println!();
        println!("Tip: For feature report access, look for the interface with");
        println!("Usage Page 0x0001 (Generic Desktop) or a vendor-specific page.");
    }

    Ok(())
}

/// Open the DualSense Edge (or regular DualSense) device.
/// Tries Edge first, falls back to regular DualSense.
/// Prefers the gamepad interface (usage page 0x01, usage 0x05).
pub fn open_device(api: &HidApi) -> Result<(HidDevice, DeviceInfo)> {
    // Try Edge first, then regular DualSense
    for &(pid, is_edge) in &[(DUALSENSE_EDGE_PID, true), (DUALSENSE_PID, false)] {
        // First pass: look for gamepad usage (0x01/0x05)
        for device_info in api.device_list() {
            if device_info.vendor_id() != SONY_VID || device_info.product_id() != pid {
                continue;
            }
            if device_info.usage_page() == 0x0001 && device_info.usage() == 0x0005 {
                let info = device_info_from(device_info, is_edge);
                match device_info.open_device(api) {
                    Ok(dev) => return Ok((dev, info)),
                    Err(e) => {
                        if e.to_string().contains("Access denied")
                            || e.to_string().contains("permission")
                        {
                            return Err(HidError::PermissionDenied);
                        }
                        // Try next interface
                        continue;
                    }
                }
            }
        }

        // Second pass: try any interface for this PID
        for device_info in api.device_list() {
            if device_info.vendor_id() != SONY_VID || device_info.product_id() != pid {
                continue;
            }
            let info = device_info_from(device_info, is_edge);
            match device_info.open_device(api) {
                Ok(dev) => return Ok((dev, info)),
                Err(e) => {
                    if e.to_string().contains("Access denied")
                        || e.to_string().contains("permission")
                    {
                        return Err(HidError::PermissionDenied);
                    }
                    continue;
                }
            }
        }
    }

    Err(HidError::NotFound)
}

fn device_info_from(d: &hidapi::DeviceInfo, is_edge: bool) -> DeviceInfo {
    DeviceInfo {
        path: d.path().to_string_lossy().into_owned(),
        vid: d.vendor_id(),
        pid: d.product_id(),
        interface: d.interface_number(),
        usage_page: d.usage_page(),
        usage: d.usage(),
        manufacturer: d.manufacturer_string().unwrap_or_default().to_string(),
        product: d.product_string().unwrap_or_default().to_string(),
        serial: d.serial_number().unwrap_or_default().to_string(),
        is_edge,
    }
}
