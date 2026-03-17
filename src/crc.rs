use crate::reports::DeviceDump;
use colored::Colorize;
use crc::{Crc, CRC_32_CKSUM, CRC_32_ISO_HDLC, CRC_32_JAMCRC, CRC_32_MPEG_2};
use std::fs;
use std::path::Path;

/// Known CRC algorithms to try
struct CrcCandidate {
    name: &'static str,
    algo: Crc<u32>,
}

fn candidates() -> Vec<CrcCandidate> {
    vec![
        CrcCandidate {
            name: "CRC-32/ISO-HDLC (standard)",
            algo: Crc::<u32>::new(&CRC_32_ISO_HDLC),
        },
        CrcCandidate {
            name: "CRC-32/JAMCRC",
            algo: Crc::<u32>::new(&CRC_32_JAMCRC),
        },
        CrcCandidate {
            name: "CRC-32/MPEG-2",
            algo: Crc::<u32>::new(&CRC_32_MPEG_2),
        },
        CrcCandidate {
            name: "CRC-32/CKSUM",
            algo: Crc::<u32>::new(&CRC_32_CKSUM),
        },
    ]
}

/// DualSense-specific CRC: CRC32 with a seed byte prepended.
/// The standard DualSense uses seed 0xA2 for output reports.
/// Try various seeds for feature reports.
fn dualsense_crc32(data: &[u8], seed: u8) -> u32 {
    let algo = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    let mut digest = algo.digest();
    digest.update(&[seed]);
    digest.update(data);
    digest.finalize()
}

pub fn find_crc(dump_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let dump: DeviceDump = serde_json::from_str(&fs::read_to_string(dump_path)?)?;

    println!(
        "Analyzing CRC in {} ({} reports)\n",
        dump_path.display(),
        dump.reports.len()
    );

    let algos = candidates();

    for report in &dump.reports {
        if report.data.len() < 5 {
            continue; // Too short for CRC32 + meaningful data
        }

        let data = &report.data;
        let len = data.len();

        // Try last 4 bytes as CRC32
        let tail_crc = u32::from_le_bytes([data[len - 4], data[len - 3], data[len - 2], data[len - 1]]);
        let body = &data[..len - 4];

        // Standard CRC algorithms over the body
        for candidate in &algos {
            let computed = candidate.algo.checksum(body);
            if computed == tail_crc {
                println!(
                    "{}",
                    format!(
                        "Report 0x{:02X} ({} bytes): MATCH with {} (tail CRC: 0x{:08X})",
                        report.report_id, len, candidate.name, tail_crc
                    )
                    .green()
                    .bold()
                );
            }
        }

        // DualSense-specific: CRC32 with seed byte prepended
        // Try common seeds
        for seed in [0xA1, 0xA2, 0xA3, 0x00, 0xFF, report.report_id] {
            let computed = dualsense_crc32(body, seed);
            if computed == tail_crc {
                println!(
                    "{}",
                    format!(
                        "Report 0x{:02X} ({} bytes): MATCH with DualSense CRC32 seed=0x{:02X} (tail CRC: 0x{:08X})",
                        report.report_id, len, seed, tail_crc
                    )
                    .green()
                    .bold()
                );
            }
        }

        // Also try CRC over body excluding the report ID byte (byte 0)
        if body.len() > 1 {
            let body_no_id = &body[1..];
            for candidate in &algos {
                let computed = candidate.algo.checksum(body_no_id);
                if computed == tail_crc {
                    println!(
                        "{}",
                        format!(
                            "Report 0x{:02X} ({} bytes): MATCH with {} (excl. report ID) (tail CRC: 0x{:08X})",
                            report.report_id, len, candidate.name, tail_crc
                        )
                        .green()
                        .bold()
                    );
                }
            }

            for seed in [0xA1, 0xA2, 0xA3, 0x00, 0xFF, report.report_id] {
                let computed = dualsense_crc32(body_no_id, seed);
                if computed == tail_crc {
                    println!(
                        "{}",
                        format!(
                            "Report 0x{:02X} ({} bytes): MATCH with DualSense CRC32 seed=0x{:02X} (excl. report ID) (tail CRC: 0x{:08X})",
                            report.report_id, len, seed, tail_crc
                        )
                        .green()
                        .bold()
                    );
                }
            }
        }

        // Try big-endian CRC interpretation
        let tail_crc_be =
            u32::from_be_bytes([data[len - 4], data[len - 3], data[len - 2], data[len - 1]]);
        if tail_crc_be != tail_crc {
            for candidate in &algos {
                let computed = candidate.algo.checksum(body);
                if computed == tail_crc_be {
                    println!(
                        "{}",
                        format!(
                            "Report 0x{:02X} ({} bytes): MATCH with {} (BE) (tail CRC: 0x{:08X})",
                            report.report_id, len, candidate.name, tail_crc_be
                        )
                        .green()
                        .bold()
                    );
                }
            }
        }
    }

    println!("\n{}", "CRC analysis complete.".cyan());
    println!("If no matches found, the checksum may use:");
    println!("  - A different polynomial or init value");
    println!("  - CRC16 instead of CRC32");
    println!("  - A custom algorithm");
    println!("  - No checksum at all for some reports");
    Ok(())
}

/// Brute-force CRC seed byte for a specific CRC value and data body.
fn brute_force_seed(body: &[u8], target_crc: u32) -> Option<u8> {
    let algo = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    for seed in 0x00..=0xFFu8 {
        let mut digest = algo.digest();
        digest.update(&[seed]);
        digest.update(body);
        if digest.finalize() == target_crc {
            return Some(seed);
        }
    }
    None
}

/// Targeted CRC analysis for Edge profile reports.
/// The profile CRC32 is at buf2[56..60], computed over the 3 buffers.
pub fn find_profile_crc(dump_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let dump: DeviceDump = serde_json::from_str(&fs::read_to_string(dump_path)?)?;

    // Collect profile triplets
    let mut report_map = std::collections::HashMap::new();
    for r in &dump.reports {
        report_map.insert(r.report_id, r.data.as_slice());
    }

    let profile_bases: [u8; 4] = [0x70, 0x73, 0x76, 0x79];
    let algos = candidates();

    println!("{}", "=== Profile CRC32 Analysis ===\n".cyan().bold());

    for &base in &profile_bases {
        let buf0 = match report_map.get(&base) {
            Some(b) => *b,
            None => continue,
        };
        let buf1 = match report_map.get(&(base + 1)) {
            Some(b) => *b,
            None => continue,
        };
        let buf2 = match report_map.get(&(base + 2)) {
            Some(b) => *b,
            None => continue,
        };

        if buf2.len() < 60 {
            continue;
        }

        // CRC is at buf2[56..60]
        let stored_crc = u32::from_le_bytes([buf2[56], buf2[57], buf2[58], buf2[59]]);
        let slot = (base - 0x70) / 3;
        println!(
            "Profile slot {} (reports 0x{:02X}-0x{:02X}): stored CRC = 0x{:08X}",
            slot, base, base + 2, stored_crc
        );

        // Try various CRC scopes
        let scopes: Vec<(&str, Vec<u8>)> = vec![
            // Scope 1: All 3 buffers concatenated (excl CRC field)
            ("all 3 bufs concat", {
                let mut v = Vec::new();
                v.extend_from_slice(buf0);
                v.extend_from_slice(buf1);
                v.extend_from_slice(&buf2[..56]);
                v
            }),
            // Scope 2: All 3 bufs, skip report ID byte from each
            ("all 3 bufs, skip report IDs", {
                let mut v = Vec::new();
                v.extend_from_slice(&buf0[1..]);
                v.extend_from_slice(&buf1[1..]);
                v.extend_from_slice(&buf2[1..56]);
                v
            }),
            // Scope 3: Just buf2 up to CRC
            ("buf2 only [0..56]", buf2[..56].to_vec()),
            // Scope 4: buf2 skip report ID
            ("buf2 only [1..56]", buf2[1..56].to_vec()),
            // Scope 5: All 3 full bufs (64 bytes each, no exclusion of CRC)
            ("all 3 bufs full 192 bytes", {
                let mut v = Vec::new();
                v.extend_from_slice(buf0);
                v.extend_from_slice(buf1);
                v.extend_from_slice(buf2);
                v
            }),
        ];

        // The actual CRC scope from the community WebHID app:
        // CRC32(buf0[2..60] + buf1[2..60] + buf2[2..56]) = 170 bytes, no seed
        let actual_scope: Vec<u8> = {
            let mut v = Vec::with_capacity(170);
            v.extend_from_slice(&buf0[2..60.min(buf0.len())]);
            v.extend_from_slice(&buf1[2..60.min(buf1.len())]);
            v.extend_from_slice(&buf2[2..56.min(buf2.len())]);
            v
        };
        println!("  CRC scope: buf0[2..60] + buf1[2..60] + buf2[2..56] = {} bytes", actual_scope.len());

        // Try all algorithms with actual scope
        for candidate in &algos {
            let computed = candidate.algo.checksum(&actual_scope);
            if computed == stored_crc {
                println!(
                    "  {}",
                    format!("MATCH: {} (no seed)", candidate.name)
                        .green()
                        .bold()
                );
            }
        }

        // Brute-force seed on actual scope
        if let Some(seed) = brute_force_seed(&actual_scope, stored_crc) {
            println!(
                "  {}",
                format!("MATCH: CRC32/ISO-HDLC seed=0x{:02X}", seed)
                    .green()
                    .bold()
            );
        }

        // Also try the other scopes for completeness
        for (scope_name, body) in &scopes {
            for candidate in &algos {
                let computed = candidate.algo.checksum(body);
                if computed == stored_crc {
                    println!(
                        "  {}",
                        format!("MATCH: {} over {}", candidate.name, scope_name)
                            .green()
                            .bold()
                    );
                }
            }
            if let Some(seed) = brute_force_seed(body, stored_crc) {
                println!(
                    "  {}",
                    format!(
                        "MATCH: CRC32/ISO-HDLC seed=0x{:02X} over {}",
                        seed, scope_name
                    )
                    .green()
                    .bold()
                );
            }
        }
        println!();
    }

    Ok(())
}
