// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::error::*;
mod ioctl;
pub use ioctl::*;
mod types;
use crate::certs::{builtin::HRK, ca, csv, Verifiable};
use codicon::Decoder;
use log::*;
use std::fs::{self, File, OpenOptions};
use std::io::{self};
use std::path::Path;
pub use types::*;

/// Reads the DCU ID from the sysfs topology node.
fn topology_sysfs_get_dcu_id(sysfs_node_id: u32) -> io::Result<u32> {
    let path = format!(
        "/sys/devices/virtual/kfd/kfd/topology/nodes/{}/gpu_id",
        sysfs_node_id
    );
    fs::read_to_string(&path)?
        .trim()
        .parse::<u32>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse DCU ID"))
}

/// Counts the number of subdirectories in a given directory with an optional prefix filter.
fn num_subdirs(dirpath: &str, prefix: &str) -> usize {
    fs::read_dir(dirpath)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    let name = entry.file_name();
                    let name_lossy = name.to_string_lossy();
                    !(name_lossy == "." || name_lossy == "..")
                        && (prefix.is_empty() || name_lossy.starts_with(prefix))
                })
                .count()
        })
        .unwrap_or(0)
}

/// A handle to the dcu device.
pub struct DcuDevice(File);

impl DcuDevice {
    /// Opens a handle to the DCU device via `/dev/mkfd`.
    pub fn new() -> io::Result<DcuDevice> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/mkfd")
            .map(DcuDevice)
    }

    /// Get attestation reports from all available DCU nodes
    ///
    /// # Arguments
    /// * `userdata` - 64-byte user data value used for attestation request
    ///
    /// # Returns
    /// - `Ok(Vec<AttestationReport>)` containing valid attestation reports
    /// - `Err(Error)` if:
    ///   - No valid reports are obtained
    ///   - IOCTL operations fail
    ///   - DCU node communication fails
    pub fn get_report(&mut self, userdata: [u8; 64]) -> Result<Vec<AttestationReport>, Error> {
        // Discover available DCU nodes
        let num_node = num_subdirs("/sys/devices/virtual/kfd/kfd/topology/nodes", "");
        let mut reports: Vec<AttestationReport> = Vec::with_capacity(num_node);
        let hyflash_path = [
            "/usr/local/hyhal/firmware/vbios/hyflash",
            "/usr/local/hyhal/firmware/vbios/hyflash_x86",
            "/opt/hyhal/vbios/hyflash_x86",
            "/opt/hyhal/firmware/vbios/hyflash",
            "/opt/hyhal/firmware/vbios/hyflash_x86",
        ]
        .into_iter()
        .find(|path| Path::new(path).exists());

        // Number of topology nodes that were skipped because they do not map to
        // a DCU (e.g. the CPU node). hyflash only enumerates DCUs, so these have
        // to be discounted when translating a topology node index into a
        // hyflash `--node` index.
        let mut invalid_dcu_count: usize = 0;

        // Process each DCU node
        for node in 0..num_node {
            trace!("Processing node {} of {}", node, num_node);

            if let Ok(dcu_id) = topology_sysfs_get_dcu_id(node as u32) {
                trace!("Found DCU ID: {}", dcu_id);

                // Skip invalid DCU IDs
                if dcu_id == 0 {
                    invalid_dcu_count += 1;
                    continue;
                }

                if let Some(path) = hyflash_path {
                    // --node argument for hyflash
                    let node_index = node.saturating_sub(invalid_dcu_count);
                    // Run hyflash to query the security state. The command's
                    // exit status is not checked; only the captured output is
                    // inspected for "SECURE" to skip non-SECURE nodes.
                    let output = std::process::Command::new(path)
                        .arg("--node")
                        .arg(node_index.to_string())
                        .arg("--securityState")
                        .output();

                    if let Ok(output) = output {
                        let output_text = format!(
                            "{}{}",
                            String::from_utf8_lossy(&output.stdout),
                            String::from_utf8_lossy(&output.stderr)
                        );
                        if !output_text.contains("SECURE") {
                            trace!("Node {} (DCU ID {}) is not SECURE, skipping", node, dcu_id);
                            continue;
                        }
                    }
                } else {
                    trace!("hyflash_x86 not found, skipping security-state check");
                }
                // Initialize attestation request
                let mut args = MkfdIoctlSecurityAttestationArgs::new();
                args.set_attestation_args(dcu_id, userdata)?;

                // Execute IOCTL request
                if DCU_GET_REPORT.ioctl(&mut self.0, &mut args)? == 0 {
                    if let Some(report) = args.extract_report()? {
                        debug!(
                            "Get dcu report succeeded - Node: {}, DCU ID: {}",
                            node, dcu_id
                        );
                        // Debug output and storage
                        report.print_report();
                        reports.push(report);
                    }
                }
            }
        }

        // Validate we got at least one report
        if reports.is_empty() {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No valid attestation reports obtained from any DCU node",
            )
            .into())
        } else {
            Ok(reports)
        }
    }
}

/// Verifies multiple attestation reports asynchronously.
///
/// Iterates through each report, retrieves the corresponding certificate (either from local storage
/// or by downloading), and performs full verification including certificate chain validation and nonce matching.
///
/// # Arguments
/// * `reports` - Slice of [`AttestationReport`] structures to verify
/// * `userdata` - 64-byte expected nonce value (must match each report's embedded user data)
///
/// # Returns
/// * `Ok(())` if all reports pass verification
/// * `Err(Error)` containing the first encountered verification failure
#[cfg(feature = "network")]
pub async fn verify_reports(
    reports: &[AttestationReport],
    userdata: &[u8; 64],
) -> Result<(), Error> {
    for report in reports {
        let cert_data = csv::cert::get_certificate_data(&report.body.chip_id).await?;
        verify_report(report, userdata, &cert_data)?;
    }
    Ok(())
}

/// Performs complete verification of a single attestation report.
///
/// # Verification Pipeline
/// 1. ​**Nonce Verification**:
///    - Compares provided mnonce with report's embedded nonce
/// 2. ​**Certificate Chain Decoding**:
///    - HRK (Hygon Root Key) ← Predefined
///    - HSK (Hygon Signing Key) ← From cert_data
///    - CEK (Chip Endorsement Key) ← From cert_data
/// 3. ​**Certificate Chain Validation**:
///    - HRK → HSK → CEK → Report signature
///
/// # Arguments
/// * `report` - Individual attestation report to verify
/// * `mnonce` - Expected 16-byte nonce value
/// * `cert_data` - DER-encoded certificate chain (HSK + CEK)
///
/// # Errors
/// Returns specific validation errors for:
/// - Certificate decoding failures
/// - Chain validation failures
/// - Nonce mismatches
pub fn verify_report(
    report: &AttestationReport,
    userdata: &[u8; 64],
    cert_data: &[u8],
) -> Result<(), Error> {
    let mut cert_slice = cert_data;

    // Decode certificate chain
    let hsk = ca::Certificate::decode(&mut cert_slice, ())?;
    let cek = csv::Certificate::decode(&mut cert_slice, ())?;
    let hrk = ca::Certificate::decode(&mut &HRK[..], ())?;

    report.print_report();

    // Critical security check: nonce matching
    if userdata != &report.body.user_data {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "Attestation nonce mismatch").into(),
        );
    }

    // Validate certificate hierarchy
    (&hrk, &hrk).verify()?; // HRK self-verification
    (&hrk, &hsk).verify()?; // HRK → HSK
    (&hsk, &cek).verify()?; // HSK → CEK
    (&cek, report).verify()?; // CEK → Report

    debug!(
        "Successfully verified report for Chip ID: {}",
        String::from_utf8_lossy(&report.body.chip_id)
    );

    Ok(())
}

/// Saves certificates to local files
pub fn save_certificates(
    hsk: &ca::Certificate,
    cek: &csv::Certificate,
    hrk: &ca::Certificate,
    chip_id: [u8; 16],
) -> Result<(), Error> {
    // Define certificates directory path
    let certs_dir = Path::new("/opt/dcu/certs");

    // Create directory recursively if it doesn't exist (similar to mkdir -p)
    if !certs_dir.exists() {
        fs::create_dir_all(certs_dir).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    }

    // Write HSK certificate
    hsk.write_to_file(&certs_dir.join("hsk.cert"))?;

    // Convert chip_id to string
    let chip_id_str = String::from_utf8(chip_id.to_vec())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Write CEK certificate (with chip_id in filename)
    cek.write_to_file(&certs_dir.join(format!("{}_cek.cert", chip_id_str)))?;

    // Write HRK certificate
    hrk.write_to_file(&certs_dir.join("hrk.cert"))?;

    Ok(())
}
