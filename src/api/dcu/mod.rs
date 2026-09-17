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
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self};
use std::path::Path;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::{Duration, Instant};
pub use types::*;

const KFD_TOPOLOGY_NODES: &str = "/sys/devices/virtual/kfd/kfd/topology/nodes";
const HYFLASH_PATHS: [&str; 5] = [
    "/usr/local/hyhal/firmware/vbios/hyflash",
    "/usr/local/hyhal/firmware/vbios/hyflash_x86",
    "/opt/hyhal/vbios/hyflash_x86",
    "/opt/hyhal/firmware/vbios/hyflash",
    "/opt/hyhal/firmware/vbios/hyflash_x86",
];
const HYFLASH_TIMEOUT: Duration = Duration::from_secs(15);
static HYFLASH_QUERY_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct PciAddress {
    domain: u16,
    bus: u8,
    device: u8,
    function: u8,
}

#[derive(Clone, Copy, Debug)]
struct DcuTopologyNode {
    node_id: u32,
    dcu_id: u32,
    pci_address: PciAddress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DcuSecurityState {
    Proto,
    Secure,
}

impl PciAddress {
    fn parse(value: &str) -> Option<Self> {
        let (address, function) = value.split_once('.')?;
        let mut address_parts = address.split(':');
        let domain = u16::from_str_radix(address_parts.next()?, 16).ok()?;
        let bus = u8::from_str_radix(address_parts.next()?, 16).ok()?;
        let device = u8::from_str_radix(address_parts.next()?, 16).ok()?;
        if address_parts.next().is_some() || device > 0x1f {
            return None;
        }
        let function = u8::from_str_radix(function, 16).ok()?;
        if function > 0x7 {
            return None;
        }

        Some(Self {
            domain,
            bus,
            device,
            function,
        })
    }

    fn from_kfd_properties(properties: &str) -> io::Result<Self> {
        let location_id = topology_property(properties, "location_id")
            .ok_or_else(|| invalid_topology_property("location_id is missing"))
            .and_then(parse_topology_u32)?;
        let domain = topology_property(properties, "domain")
            .ok_or_else(|| invalid_topology_property("domain is missing"))
            .and_then(parse_topology_u32)?;

        if location_id > u16::MAX as u32 {
            return Err(invalid_topology_property("location_id is out of range"));
        }
        if domain > u16::MAX as u32 {
            return Err(invalid_topology_property("domain is out of range"));
        }

        Ok(Self {
            domain: domain as u16,
            bus: ((location_id >> 8) & 0xff) as u8,
            device: ((location_id >> 3) & 0x1f) as u8,
            function: (location_id & 0x7) as u8,
        })
    }
}

impl fmt::Display for PciAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:04x}:{:02x}:{:02x}.{}",
            self.domain, self.bus, self.device, self.function
        )
    }
}

fn invalid_topology_property(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn topology_property<'a>(properties: &'a str, property: &str) -> Option<&'a str> {
    properties.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        if fields.next()? == property {
            fields.next()
        } else {
            None
        }
    })
}

fn parse_topology_u32(value: &str) -> io::Result<u32> {
    let parsed = if let Some(value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(value, 16)
    } else {
        value.parse::<u32>()
    };
    parsed.map_err(|_| invalid_topology_property("failed to parse topology property"))
}

/// Reads the DCU ID from the sysfs topology node.
fn topology_sysfs_get_dcu_id(sysfs_node_id: u32) -> io::Result<u32> {
    let path = format!("{KFD_TOPOLOGY_NODES}/{sysfs_node_id}/gpu_id");
    fs::read_to_string(&path)?
        .trim()
        .parse::<u32>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse DCU ID"))
}

/// Reads the PCI address encoded by the KFD topology node properties.
fn topology_sysfs_get_pci_address(sysfs_node_id: u32) -> io::Result<PciAddress> {
    let path = format!("{KFD_TOPOLOGY_NODES}/{sysfs_node_id}/properties");
    PciAddress::from_kfd_properties(&fs::read_to_string(path)?)
}

fn discover_dcu_topology_nodes() -> io::Result<Vec<DcuTopologyNode>> {
    let mut node_ids = Vec::new();
    for entry in fs::read_dir(KFD_TOPOLOGY_NODES)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let Ok(node_id) = name.parse::<u32>() else {
            trace!("Ignoring non-numeric KFD topology entry: {name}");
            continue;
        };
        node_ids.push(node_id);
    }
    node_ids.sort_unstable();

    let mut dcu_nodes = Vec::with_capacity(node_ids.len());
    for node_id in node_ids {
        let dcu_id = topology_sysfs_get_dcu_id(node_id).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("Failed to read GPU ID for KFD topology node {node_id}: {error}"),
            )
        })?;
        if dcu_id == 0 {
            continue;
        }
        let pci_address = topology_sysfs_get_pci_address(node_id).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "Failed to determine PCI address for KFD topology node {node_id} \
                     (DCU ID {dcu_id}): {error}"
                ),
            )
        })?;
        dcu_nodes.push(DcuTopologyNode {
            node_id,
            dcu_id,
            pci_address,
        });
    }

    if dcu_nodes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No DCU GPU nodes found in KFD topology",
        ));
    }
    Ok(dcu_nodes)
}

/// Parses one `hyflash --node a --securityState` output line.
///
/// Expected lines contain a PCI address followed by `Security state: STATE`.
/// The state must be the final token so values such as `INSECURE` or text that
/// merely contains `SECURE` cannot be mistaken for the secure state.
fn parse_hyflash_security_state_line(
    line: &str,
) -> io::Result<Option<(PciAddress, DcuSecurityState)>> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let Some(marker_index) = fields.windows(2).position(|pair| {
        pair[0].eq_ignore_ascii_case("security")
            && pair[1].trim_end_matches(':').eq_ignore_ascii_case("state")
    }) else {
        return Ok(None);
    };

    let state_index = if fields[marker_index + 1].ends_with(':') {
        marker_index + 2
    } else if fields.get(marker_index + 2) == Some(&":") {
        marker_index + 3
    } else {
        marker_index + 2
    };
    if state_index + 1 != fields.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("malformed hyflash security-state record: {line}"),
        ));
    }

    let pci_address = fields[..marker_index]
        .iter()
        .find_map(|field| PciAddress::parse(field))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("hyflash security-state record has no valid PCI address: {line}"),
            )
        })?;
    let state = match fields[state_index] {
        state if state.eq_ignore_ascii_case("SECURE") => DcuSecurityState::Secure,
        state if state.eq_ignore_ascii_case("PROTO") => DcuSecurityState::Proto,
        state => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("hyflash reported unsupported security state {state:?} for {pci_address}"),
            ));
        }
    };
    Ok(Some((pci_address, state)))
}

fn parse_hyflash_security_states(output: &str) -> io::Result<Vec<(PciAddress, DcuSecurityState)>> {
    output
        .lines()
        .map(parse_hyflash_security_state_line)
        .filter_map(Result::transpose)
        .collect()
}

fn secure_pci_addresses_from_hyflash_output(
    hyflash_path: &str,
    output: &str,
    expected_addresses: &HashSet<PciAddress>,
) -> io::Result<HashSet<PciAddress>> {
    let states = parse_hyflash_security_states(output)?;
    if states.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{hyflash_path} returned no parseable DCU security-state records"),
        ));
    }
    let mut reported_states = HashMap::with_capacity(states.len());
    for (address, state) in states {
        if let Some(previous_state) = reported_states.insert(address, state) {
            if previous_state != state {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{hyflash_path} reported conflicting security states for {address}"),
                ));
            }
        }
    }

    let mut missing_addresses: Vec<_> = expected_addresses
        .iter()
        .filter(|address| !reported_states.contains_key(address))
        .copied()
        .collect();
    if !missing_addresses.is_empty() {
        missing_addresses.sort_unstable();
        let missing_addresses = missing_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{hyflash_path} output is missing KFD GPU BDF record(s): {missing_addresses}"),
        ));
    }

    let mut unexpected_addresses: Vec<_> = reported_states
        .keys()
        .filter(|address| !expected_addresses.contains(address))
        .copied()
        .collect();
    if !unexpected_addresses.is_empty() {
        unexpected_addresses.sort_unstable();
        let unexpected_addresses = unexpected_addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{hyflash_path} output contains unexpected DCU BDF record(s): \
                 {unexpected_addresses}"
            ),
        ));
    }

    let secure_addresses: HashSet<_> = reported_states
        .into_iter()
        .filter_map(|(address, state)| (state == DcuSecurityState::Secure).then_some(address))
        .collect();
    if secure_addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("{hyflash_path} reported no SECURE DCU adapters"),
        ));
    }
    Ok(secure_addresses)
}

/// Queries all adapters once and returns the PCI addresses of secure DCUs.
///
/// Queries one hyflash binary. Exit code 255 is the only known non-zero status
/// emitted alongside complete, valid output, so all other failures are rejected.
fn query_secure_dcu_pci_addresses_with(
    hyflash_path: &str,
    expected_addresses: &HashSet<PciAddress>,
) -> io::Result<HashSet<PciAddress>> {
    let mut child = std::process::Command::new(hyflash_path)
        .arg("--node")
        .arg("a")
        .arg("--securityState")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("Failed to execute {hyflash_path} for DCU security states: {error}"),
            )
        })?;

    let started = Instant::now();
    loop {
        match child.try_wait()? {
            Some(_) => break,
            None if started.elapsed() >= HYFLASH_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "{hyflash_path} did not return security states within {} seconds",
                        HYFLASH_TIMEOUT.as_secs()
                    ),
                ));
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    let output = child.wait_with_output()?;

    let output_text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let exit_code_is_accepted = output.status.success() || output.status.code() == Some(255);
    if !exit_code_is_accepted {
        return Err(io::Error::other(format!(
            "hyflash exit status was {}",
            output.status
        )));
    }

    let secure_addresses =
        secure_pci_addresses_from_hyflash_output(hyflash_path, &output_text, expected_addresses)?;
    if output.status.code() == Some(255) {
        warn!(
            "{hyflash_path} --node a --securityState exited with the known status 255, \
             but its output contained complete records for all {} KFD GPU(s); \
             accepting the output",
            expected_addresses.len()
        );
    }
    trace!(
        "hyflash reported {} secure DCU adapter(s)",
        secure_addresses.len()
    );
    Ok(secure_addresses)
}

/// Tries every installed hyflash candidate until one returns a complete and
/// internally consistent view. This avoids a stale helper shadowing a newer one.
fn query_secure_dcu_pci_addresses(
    expected_addresses: &HashSet<PciAddress>,
) -> io::Result<HashSet<PciAddress>> {
    let _query_guard = HYFLASH_QUERY_LOCK
        .lock()
        .map_err(|_| io::Error::other("hyflash security-state query lock is poisoned"))?;
    let mut errors = Vec::new();
    for hyflash_path in HYFLASH_PATHS {
        if !Path::new(hyflash_path).is_file() {
            continue;
        }
        match query_secure_dcu_pci_addresses_with(hyflash_path, expected_addresses) {
            Ok(addresses) => return Ok(addresses),
            Err(error) => {
                warn!("Rejecting security-state result from {hyflash_path}: {error}");
                errors.push(format!("{hyflash_path}: {error}"));
            }
        }
    }

    if errors.is_empty() {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("hyflash not found; checked: {}", HYFLASH_PATHS.join(", ")),
        ))
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "no hyflash candidate returned trustworthy security states: {}",
                errors.join("; ")
            ),
        ))
    }
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
    ///   - DCU security-state discovery or BDF mapping fails
    ///   - IOCTL operations fail
    ///   - DCU node communication fails
    pub fn get_report(&mut self, userdata: [u8; 64]) -> Result<Vec<AttestationReport>, Error> {
        // Discover all KFD GPU nodes before querying hyflash so output coverage
        // can be validated before any DCU IOCTL is issued.
        let dcu_nodes = discover_dcu_topology_nodes()?;
        let expected_pci_addresses: HashSet<_> =
            dcu_nodes.iter().map(|node| node.pci_address).collect();
        let mut reports: Vec<AttestationReport> = Vec::with_capacity(dcu_nodes.len());
        let secure_pci_addresses = query_secure_dcu_pci_addresses(&expected_pci_addresses)?;

        // Process each DCU node
        for DcuTopologyNode {
            node_id,
            dcu_id,
            pci_address,
        } in dcu_nodes
        {
            trace!("Processing KFD GPU node {node_id} (DCU ID {dcu_id}, PCI {pci_address})");
            if !secure_pci_addresses.contains(&pci_address) {
                trace!(
                    "Node {node_id} (DCU ID {dcu_id}, PCI {pci_address}) is not SECURE, skipping"
                );
                continue;
            }
            trace!("Node {node_id} (DCU ID {dcu_id}, PCI {pci_address}) is SECURE");

            // Initialize the request only after the node's BDF was confirmed SECURE.
            let mut args = MkfdIoctlSecurityAttestationArgs::new();
            args.set_attestation_args(dcu_id, userdata)?;

            // Execute IOCTL request. A failure for a SECURE card is propagated.
            let ioctl_result = DCU_GET_REPORT.ioctl(&mut self.0, &mut args)?;
            if ioctl_result != 0 {
                return Err(io::Error::other(format!(
                    "DCU report IOCTL returned {ioctl_result} for SECURE node {node_id} \
                     (DCU ID {dcu_id}, PCI {pci_address})"
                ))
                .into());
            }
            if args.fw_err != 0 {
                return Err(io::Error::other(format!(
                    "DCU report firmware returned error {:#x} for SECURE node {node_id} \
                     (DCU ID {dcu_id}, PCI {pci_address})",
                    args.fw_err
                ))
                .into());
            }
            if let Some(report) = args.extract_report()? {
                debug!(
                    "Get dcu report succeeded - Node: {node_id}, DCU ID: {dcu_id}, \
                     PCI: {pci_address}"
                );
                // Debug output and storage
                report.print_report();
                reports.push(report);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hyflash_security_states_by_exact_final_token() {
        let output = r#"
adapter 0 0000:41:00.0 Security state: PROTO
adapter 5 0000:c1:00.0 Security state: SECURE
adapter 6 0000:c2:00.0 security STATE: secure
unrelated SECURE output
"#;

        assert_eq!(
            parse_hyflash_security_states(output).unwrap(),
            vec![
                (
                    PciAddress {
                        domain: 0,
                        bus: 0x41,
                        device: 0,
                        function: 0,
                    },
                    DcuSecurityState::Proto,
                ),
                (
                    PciAddress {
                        domain: 0,
                        bus: 0xc1,
                        device: 0,
                        function: 0,
                    },
                    DcuSecurityState::Secure,
                ),
                (
                    PciAddress {
                        domain: 0,
                        bus: 0xc2,
                        device: 0,
                        function: 0,
                    },
                    DcuSecurityState::Secure,
                ),
            ]
        );

        let error =
            parse_hyflash_security_states("adapter 7 0000:c3:00.0 Security state: INSECURE")
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let error = parse_hyflash_security_states(
            "adapter 8 0000:c4:00.0 Security state: SECURE trailing-text",
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn converts_kfd_location_and_domain_to_pci_address() {
        let properties = "cpu_cores_count 0\nsimd_count 64\nlocation_id 49408\ndomain 0\n";

        assert_eq!(
            PciAddress::from_kfd_properties(properties).unwrap(),
            PciAddress {
                domain: 0,
                bus: 0xc1,
                device: 0,
                function: 0,
            }
        );

        let location_id = (0x4b_u32 << 8) | (0x1d << 3) | 0x7;
        let properties = format!("location_id 0x{location_id:x}\ndomain 0x12\n");
        assert_eq!(
            PciAddress::from_kfd_properties(&properties).unwrap(),
            PciAddress {
                domain: 0x12,
                bus: 0x4b,
                device: 0x1d,
                function: 0x7,
            }
        );
    }

    #[test]
    fn parses_and_formats_pci_addresses() {
        let address = PciAddress::parse("0001:C1:1f.7").unwrap();
        assert_eq!(
            address,
            PciAddress {
                domain: 1,
                bus: 0xc1,
                device: 0x1f,
                function: 7,
            }
        );
        assert_eq!(address.to_string(), "0001:c1:1f.7");

        assert!(PciAddress::parse("0000:c1:20.0").is_none());
        assert!(PciAddress::parse("0000:c1:00.8").is_none());
        assert!(PciAddress::parse("not-a-pci-address").is_none());
    }

    #[test]
    fn hyflash_security_filter_fails_closed() {
        let bdf_41 = PciAddress::parse("0000:41:00.0").unwrap();
        let bdf_c1 = PciAddress::parse("0000:c1:00.0").unwrap();
        let expected = HashSet::from([bdf_41, bdf_c1]);

        let error =
            secure_pci_addresses_from_hyflash_output("hyflash", "unparseable output", &expected)
                .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let error = secure_pci_addresses_from_hyflash_output(
            "hyflash",
            "adapter 0 0000:41:00.0 Security state: PROTO",
            &expected,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        let secure = secure_pci_addresses_from_hyflash_output(
            "hyflash",
            "adapter 0 0000:41:00.0 Security state: PROTO\n\
             adapter 5 0000:c1:00.0 Security state: SECURE",
            &expected,
        )
        .unwrap();
        assert_eq!(secure.len(), 1);
        assert!(secure.contains(&bdf_c1));

        let error = secure_pci_addresses_from_hyflash_output(
            "hyflash",
            "adapter 0 0000:41:00.0 Security state: PROTO\n\
             adapter 5 0000:c1:00.0 Security state: PROTO",
            &expected,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);

        let error = secure_pci_addresses_from_hyflash_output(
            "hyflash",
            "adapter 0 0000:41:00.0 Security state: PROTO\n\
             adapter 5 0000:c1:00.0 Security state: SECURE\n\
             adapter 6 0000:c2:00.0 Security state: SECURE",
            &expected,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
