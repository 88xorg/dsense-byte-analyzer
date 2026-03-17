mod crc;
mod dump;
mod hid;
mod monitor;
mod profile;
mod reports;
mod snapshot;
mod usb;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "dualsense-edge-re")]
#[command(about = "DualSense Edge controller reverse engineering toolkit")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Discover connected DualSense controllers (HID API)
    Discover,

    /// Discover all USB interfaces (raw USB, bypasses macOS HID filter)
    UsbDiscover,

    /// Dump feature reports via HID API
    Dump {
        /// Output directory for dump files
        #[arg(short, long, default_value = "dumps")]
        output: PathBuf,
    },

    /// Deep probe: try all report types and command sequences
    UsbProbe,

    /// Dump feature reports via raw USB from ALL interfaces
    UsbDump {
        /// Output directory for dump files
        #[arg(short, long, default_value = "dumps")]
        output: PathBuf,
    },

    /// Monitor live input reports from the controller
    Monitor {
        /// Log raw reports to file
        #[arg(short, long)]
        log: Option<PathBuf>,
    },

    /// Diff two dump files
    Diff {
        /// First dump file (baseline)
        a: PathBuf,
        /// Second dump file (modified)
        b: PathBuf,
    },

    /// Interactive capture session for reverse engineering
    CaptureSession {
        /// Output directory for session dumps
        #[arg(short, long, default_value = "dumps")]
        output: PathBuf,
    },

    /// Capture and diff full input reports to find profile bytes
    Snapshot {
        /// Output directory
        #[arg(short, long, default_value = "dumps")]
        output: PathBuf,
    },

    /// Try to identify CRC algorithm used in feature reports
    FindCrc {
        /// Dump file to analyze
        dump: PathBuf,
    },

    /// Read Edge profile data (feature reports 0x60-0x7B)
    ReadProfiles {
        /// Output directory for dump files
        #[arg(short, long, default_value = "dumps")]
        output: PathBuf,
    },

    /// Decode and display profiles from a dump file
    DecodeProfiles {
        /// Dump file containing profile reports (from read-profiles)
        dump: PathBuf,
    },

    /// Analyze CRC algorithm for Edge profile reports specifically
    ProfileCrc {
        /// Dump file containing profile reports
        dump: PathBuf,
    },

    /// Diagnostic: test if SET_FEATURE works by echoing a profile back
    TestWrite,

    /// Write a custom stick response curve to a profile slot.
    /// Curve is 6 bytes: 3 pairs of (input_response, output_response) control points.
    /// Example anti-deadzone: --curve 30,30,140,140,225,225 starts output at 30
    /// to bypass games with built-in deadzones.
    WriteCurve {
        /// Profile slot (0-3)
        #[arg(short, long, default_value = "3")]
        slot: u8,

        /// Which stick: "left", "right", or "both"
        #[arg(short = 'k', long, default_value = "both")]
        stick: String,

        /// 6 comma-separated curve bytes (3 control point pairs).
        /// Format: p1x,p1y,p2x,p2y,p3x,p3y (each 0-255)
        #[arg(short, long)]
        curve: String,

        /// Modifier byte (0x03 for most presets, 0x04 for Precise/Steady)
        #[arg(short, long, default_value = "3")]
        modifier: u8,

        /// Profile name
        #[arg(short, long, default_value = "Anti-Deadzone")]
        name: String,

        /// Read existing profile from this dump file (preserves UUID, buttons, etc.)
        #[arg(short, long)]
        base_dump: Option<PathBuf>,

        /// Dry run — show what would be written without actually writing
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Discover => hid::discover(),
        Commands::UsbDiscover => usb::usb_discover(),
        Commands::Dump { output } => dump::dump_reports(&output),
        Commands::UsbProbe => usb::usb_probe(),
        Commands::UsbDump { output } => usb::usb_dump(&output),
        Commands::Monitor { log } => monitor::run(log.as_deref()),
        Commands::Diff { a, b } => dump::diff_dumps(&a, &b),
        Commands::CaptureSession { output } => dump::capture_session(&output),
        Commands::Snapshot { output } => snapshot::snapshot_session(&output),
        Commands::FindCrc { dump } => crc::find_crc(&dump),
        Commands::ReadProfiles { output } => usb::read_profiles(&output),
        Commands::DecodeProfiles { dump } => profile::decode_profiles(&dump),
        Commands::ProfileCrc { dump } => crc::find_profile_crc(&dump),
        Commands::TestWrite => usb::test_write(),
        Commands::WriteCurve {
            slot,
            stick,
            curve,
            modifier,
            name,
            base_dump,
            dry_run,
        } => profile::write_curve_cmd(slot, &stick, &curve, modifier, &name, base_dump.as_deref(), dry_run),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
