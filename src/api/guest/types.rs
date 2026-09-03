// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::api::guest::CSV_RTMR_REG_SIZE;
use crate::error::*;
use crate::{
    certs::{csv::Certificate, Usage, Verifiable},
    crypto::{sig::ecdsa, PublicKey, Signature},
    util::*,
};

use openssl::{
    hash::{Hasher, MessageDigest},
    pkey, sign,
};

use static_assertions::const_assert;

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::io::Write;

use bitfield::bitfield;

pub const ATTESTATION_EXT_MAGIC: [u8; 16] = *b"ATTESTATION_EXT\0";

/// Flag bit indicating the extended attestation report (i.e. `AttestationReportV2`).
pub const CSV_ATTESTATION_FLAG_REPORT_EXT: u32 = 1 << 0;

/// Flag bit indicating the CSV3 attestation report (i.e. `AttestationReportV3`).
pub const CSV_ATTESTATION_FLAG_REPORT_EXT_V3: u32 = 1 << 1;

/// The size of the host data field in the CSV3 attestation report.
pub const CSV3_HOST_DATA_SIZE: usize = 64;

/// The minimum firmware build version that supports the CSV3 attestation
/// report format (i.e. `AttestationReportV3`).
pub const CSV3_ATTESTATION_MIN_BUILD: u32 = 2387;

/// Data provieded by the guest owner for requesting an attestation report
/// from the HYGON Secure Processor.
#[repr(C)]
#[derive(PartialEq, Debug)]
pub struct ReportReq {
    /// Guest-provided data to be included in the attestation report
    pub data: [u8; 64],
    /// Guest-provided mnonce to be placed in the report to provide protection
    pub mnonce: [u8; 16],
    /// hash of [`data`] and [`mnonce`] to provide protection
    pub hash: [u8; 32],
}

impl Default for ReportReq {
    fn default() -> Self {
        Self {
            data: [0; 64],
            mnonce: [0; 16],
            hash: [0; 32],
        }
    }
}

impl ReportReq {
    pub fn new(data: Option<[u8; 64]>, mnonce: [u8; 16]) -> Result<Self, Error> {
        let mut request = Self::default();

        if let Some(data) = data {
            request.data = data;
        }

        request.mnonce = mnonce;

        request.calculate_hash()?;

        Ok(request)
    }

    fn calculate_hash(&mut self) -> Result<(), Error> {
        let mut hasher = Hasher::new(MessageDigest::sm3())?;
        hasher.update(self.data.as_ref())?;
        hasher.update(self.mnonce.as_ref())?;
        let hash = &hasher.finish()?;
        self.hash.copy_from_slice(hash.as_ref());

        Ok(())
    }
}

/// Data provieded by the guest owner for requesting an extended attestation
/// report from the HYGON Secure Processor.
#[repr(C)]
#[derive(PartialEq, Debug)]
pub struct ReportReqExt {
    /// Guest-provided data to be included in the attestation report
    pub data: [u8; 64],
    /// Guest-provided mnonce to be placed in the report to provide protection
    pub mnonce: [u8; 16],
    /// hash of [`data`] and [`mnonce`] to provide protection
    pub hash: [u8; 32],
    /// magic string to indicate extension aware request
    pub magic: [u8; 16],
    /// flags to indicate how to extend the attestation report
    pub flags: u32,
}

impl Default for ReportReqExt {
    fn default() -> Self {
        Self {
            data: [0u8; 64],
            mnonce: [0u8; 16],
            hash: [0u8; 32],
            magic: ATTESTATION_EXT_MAGIC,
            flags: 0,
        }
    }
}

impl ReportReqExt {
    pub fn new(data: Option<[u8; 64]>, mnonce: [u8; 16], flags: u32) -> Result<Self, Error> {
        let mut request = Self::default();

        if let Some(data) = data {
            request.data = data;
        }

        request.mnonce = mnonce;

        request.calculate_hash()?;

        request.flags = flags;

        Ok(request)
    }

    fn calculate_hash(&mut self) -> Result<(), Error> {
        let mut hasher = Hasher::new(MessageDigest::sm3())?;
        hasher.update(self.data.as_ref())?;
        hasher.update(self.mnonce.as_ref())?;
        let hash = &hasher.finish()?;
        self.hash.copy_from_slice(hash.as_ref());

        Ok(())
    }
}

/// Wrapper struct for both legacy attestation report and extended attestation
/// report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationReportWrapper {
    /// The magic string to indicate the attestation report type.
    magic: [u8; 16],
    /// The flags indicate how to parse the extended attestation report.
    /// Note: the bit0 of flags must be 1.
    flags: u32,
    #[serde(with = "BigArray")]
    /// Both the legacy and extended attestation report are padded to 4096 bytes.
    data: [u8; 4096],
}

impl AttestationReportWrapper {
    pub fn new(magic: [u8; 16], flags: u32, report: &mut [u8]) -> Self {
        let mut bytes = [0u8; 4096];

        let copy_len = std::cmp::min(report.len(), 4096);
        bytes[..copy_len].copy_from_slice(&report[..copy_len]);

        Self {
            magic,
            flags,
            data: bytes,
        }
    }
}

/// Enum Containing the different versions of the Attestation Report
///
/// Since the release of the firmware API version 1.4, the attestation report
/// support extended format. In order to keep backwards compatibility, use
/// enum V1(AttestationReportV1) to handling legacy attestation report.
///
/// The V2(AttestationReportV2) is referred to as extended attestation report.
///
/// The V3(AttestationReportV3) is referred to as the CSV3 attestation report
/// which additionally carries the host data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttestationReport {
    /// Version 1 of the Attestation Report returned by the firmware
    V1(AttestationReportV1),
    /// Version 2 of the Attestation Report returned by the firmware
    V2(AttestationReportV2),
    /// Version 3 of the Attestation Report returned by the firmware
    V3(AttestationReportV3),
}

impl TryFrom<&AttestationReportWrapper> for AttestationReport {
    type Error = std::io::Error;

    fn try_from(report_wrapper: &AttestationReportWrapper) -> Result<Self, Self::Error> {
        match (report_wrapper.magic, report_wrapper.flags) {
            (magic, _) if magic == *b"\0".repeat(16) => {
                let report_v1: AttestationReportV1 = TryFrom::try_from(&report_wrapper.data[..])?;
                Ok(AttestationReport::V1(report_v1))
            }
            (ATTESTATION_EXT_MAGIC, 0) => {
                let report_v1: AttestationReportV1 = TryFrom::try_from(&report_wrapper.data[..])?;
                Ok(AttestationReport::V1(report_v1))
            }
            (ATTESTATION_EXT_MAGIC, flags) if flags & CSV_ATTESTATION_FLAG_REPORT_EXT_V3 != 0 => {
                let report_v3: AttestationReportV3 = TryFrom::try_from(&report_wrapper.data[..])?;
                Ok(AttestationReport::V3(report_v3))
            }
            (ATTESTATION_EXT_MAGIC, flags) if flags & CSV_ATTESTATION_FLAG_REPORT_EXT != 0 => {
                let report_v2: AttestationReportV2 = TryFrom::try_from(&report_wrapper.data[..])?;
                Ok(AttestationReport::V2(report_v2))
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid AttestationReport".to_string(),
            )),
        }
    }
}

impl AttestationReport {
    /// Get version of the Attestation Report
    pub fn version(&self) -> u32 {
        match self {
            Self::V1(_) => 1,
            Self::V2(_) => 2,
            Self::V3(_) => 3,
        }
    }

    /// Get tee info of the Attestation Report
    pub fn tee_info(&self) -> TeeInfo<'_> {
        match self {
            Self::V1(report) => TeeInfo::V1(&report.tee_info),
            Self::V2(report) => TeeInfo::V2(&report.tee_info),
            Self::V3(report) => TeeInfo::V3(&report.tee_info),
        }
    }

    /// Get the tee info signer of the attestation report
    pub fn signer(&self) -> &TeeInfoSigner {
        match self {
            Self::V1(report) => &report.signer,
            Self::V2(report) => &report.signer,
            Self::V3(report) => &report.signer,
        }
    }
}

/// The response from the PSP containing the generated attestation report.
///
/// The Report is padded to exactly 4096 Bytes to make sure the page size
/// matches.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationReportV1 {
    /// The tee info generated by the firmware.
    pub tee_info: TeeInfoV1,
    /// The tee's evidence to verify the tee info's signature.
    pub signer: TeeInfoSigner,
    #[serde(with = "BigArray")]
    /// Padding bits to meet the memory page alignment.
    reserved:
        [u8; 4096 - (std::mem::size_of::<TeeInfoV1>() + std::mem::size_of::<TeeInfoSigner>())],
}

// Compile-time check that the size is what is expected.
const_assert!(std::mem::size_of::<AttestationReportV1>() == 4096);

impl Default for AttestationReportV1 {
    fn default() -> Self {
        Self {
            tee_info: Default::default(),
            signer: Default::default(),
            reserved: [0u8; 4096
                - (std::mem::size_of::<TeeInfoV1>() + std::mem::size_of::<TeeInfoSigner>())],
        }
    }
}

impl TryFrom<&[u8]> for AttestationReportV1 {
    type Error = std::io::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bincode::deserialize(bytes).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to deserialize AttestationReportV1: {}", e),
            )
        })
    }
}

/// The response from the PSP containing the generated extended attestation
/// report.
///
/// The Report is padded to exactly 4096 Bytes to make sure the page size
/// matches.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationReportV2 {
    /// The tee info generated by the firmware.
    pub tee_info: TeeInfoV2,
    /// The tee's evidence to verify the tee info's signature.
    pub signer: TeeInfoSigner,
    /// Padding bits to meet the memory page alignment.
    #[serde(with = "BigArray")]
    reserved:
        [u8; 4096 - (std::mem::size_of::<TeeInfoV2>() + std::mem::size_of::<TeeInfoSigner>())],
}

// Compile-time check that the size is what is expected.
const_assert!(std::mem::size_of::<AttestationReportV2>() == 4096);

impl Default for AttestationReportV2 {
    fn default() -> Self {
        Self {
            tee_info: Default::default(),
            signer: Default::default(),
            reserved: [0u8; 4096
                - (std::mem::size_of::<TeeInfoV2>() + std::mem::size_of::<TeeInfoSigner>())],
        }
    }
}

impl TryFrom<&[u8]> for AttestationReportV2 {
    type Error = std::io::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bincode::deserialize(bytes).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to deserialize AttestationReportV2: {}", e),
            )
        })
    }
}

/// The response from the PSP containing the generated CSV3 attestation
/// report.
///
/// The Report is padded to exactly 4096 Bytes to make sure the page size
/// matches.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationReportV3 {
    /// The tee info generated by the firmware.
    pub tee_info: TeeInfoV3,
    /// The tee's evidence to verify the tee info's signature.
    pub signer: TeeInfoSigner,
    /// Padding bits to meet the memory page alignment.
    #[serde(with = "BigArray")]
    reserved:
        [u8; 4096 - (std::mem::size_of::<TeeInfoV3>() + std::mem::size_of::<TeeInfoSigner>())],
}

// Compile-time check that the size is what is expected.
const_assert!(std::mem::size_of::<AttestationReportV3>() == 4096);

impl Default for AttestationReportV3 {
    fn default() -> Self {
        Self {
            tee_info: Default::default(),
            signer: Default::default(),
            reserved: [0u8; 4096
                - (std::mem::size_of::<TeeInfoV3>() + std::mem::size_of::<TeeInfoSigner>())],
        }
    }
}

impl TryFrom<&[u8]> for AttestationReportV3 {
    type Error = std::io::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        bincode::deserialize(bytes).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to deserialize AttestationReportV3: {}", e),
            )
        })
    }
}

/// Enum Containing the different versions of the Tee Info struct
///
/// Since the release of the firmware API version 1.4, the tee info of the
/// attestation report support extended format. In order to keep backwards
/// compatibility, use enum V1(TeeInfoV1) to handling legacy tee info of the
/// attestation report.
///
/// The V2(TeeInfoV2) is tee info struct for extended attestation report.
pub enum TeeInfo<'a> {
    /// Version 1 of Tee info
    V1(&'a TeeInfoV1),
    /// Version 2 of Tee info
    V2(&'a TeeInfoV2),
    /// Version 3 of Tee info
    V3(&'a TeeInfoV3),
}

impl TeeInfo<'_> {
    /// Restore raw field from the Tee info
    pub fn raw(&self, data: &[u8]) -> Vec<u8> {
        let mut data_bytes = data.to_vec();

        let anonce_bytes = self.anonce().to_le_bytes();

        for (index, item) in data_bytes.iter_mut().enumerate() {
            *item ^= anonce_bytes[index % 4];
        }

        data_bytes
    }

    /// Get user_pubkey_digest field
    pub fn user_pubkey_digest(&self) -> Vec<u8> {
        match *self {
            Self::V1(tee_info) => self.raw(&tee_info.user_pubkey_digest[..]),
            Self::V2(tee_info) => tee_info.user_pubkey_digest.to_vec(),
            Self::V3(tee_info) => tee_info.user_pubkey_digest.to_vec(),
        }
    }

    /// Get vm_id field
    pub fn vm_id(&self) -> Vec<u8> {
        match *self {
            Self::V1(tee_info) => self.raw(&tee_info.vm_id[..]),
            Self::V2(tee_info) => tee_info.vm_id.to_vec(),
            Self::V3(tee_info) => tee_info.vm_id.to_vec(),
        }
    }

    /// Get vm_version field
    pub fn vm_version(&self) -> Vec<u8> {
        match *self {
            Self::V1(tee_info) => self.raw(&tee_info.vm_version[..]),
            Self::V2(tee_info) => tee_info.vm_version.to_vec(),
            Self::V3(tee_info) => tee_info.vm_version.to_vec(),
        }
    }

    /// Get report_data field
    pub fn report_data(&self) -> Vec<u8> {
        match *self {
            Self::V1(tee_info) => self.raw(&tee_info.report_data[..]),
            Self::V2(tee_info) => tee_info.report_data.to_vec(),
            Self::V3(tee_info) => tee_info.report_data.to_vec(),
        }
    }

    /// Get mnonce field
    pub fn mnonce(&self) -> Vec<u8> {
        match *self {
            Self::V1(tee_info) => self.raw(&tee_info.mnonce[..]),
            Self::V2(tee_info) => tee_info.mnonce.to_vec(),
            Self::V3(tee_info) => tee_info.mnonce.to_vec(),
        }
    }

    /// Get measure field
    pub fn measure(&self) -> Vec<u8> {
        match *self {
            Self::V1(tee_info) => self.raw(&tee_info.measure[..]),
            Self::V2(tee_info) => tee_info.measure.to_vec(),
            Self::V3(tee_info) => tee_info.measure.to_vec(),
        }
    }

    /// Get policy field
    pub fn policy(&self) -> GuestPolicy {
        match *self {
            Self::V1(tee_info) => tee_info.policy.xor(&self.anonce()),
            Self::V2(tee_info) => tee_info.policy,
            Self::V3(tee_info) => tee_info.policy,
        }
    }

    /// Get sig_usage field
    pub fn sig_usage(&self) -> u32 {
        match *self {
            Self::V1(tee_info) => tee_info.sig_usage ^ self.anonce(),
            Self::V2(tee_info) => tee_info.sig_usage,
            Self::V3(tee_info) => tee_info.sig_usage,
        }
    }

    /// Get sig_algo field
    pub fn sig_algo(&self) -> u32 {
        match *self {
            Self::V1(tee_info) => tee_info.sig_algo ^ self.anonce(),
            Self::V2(tee_info) => tee_info.sig_algo,
            Self::V3(tee_info) => tee_info.sig_algo,
        }
    }

    /// Get anonce field
    pub fn anonce(&self) -> u32 {
        match *self {
            Self::V1(tee_info) => tee_info.anonce,
            Self::V2(_) => 0,
            Self::V3(_) => 0,
        }
    }

    /// Get build field
    pub fn build(&self) -> u32 {
        match *self {
            Self::V1(_) => 0,
            Self::V2(tee_info) => tee_info.build,
            Self::V3(tee_info) => tee_info.build,
        }
    }

    /// Get rtmr_version field
    pub fn rtmr_version(&self) -> u16 {
        match *self {
            Self::V1(_) => 0,
            Self::V2(tee_info) => tee_info.rtmr_version,
            Self::V3(tee_info) => tee_info.rtmr_version,
        }
    }

    /// Get rtmr0 field
    pub fn rtmr0(&self) -> &[u8] {
        match *self {
            Self::V1(_) => &[0u8; CSV_RTMR_REG_SIZE],
            Self::V2(tee_info) => &tee_info.rtmr0,
            Self::V3(tee_info) => &tee_info.rtmr0,
        }
    }

    /// Get rtmr1 field
    pub fn rtmr1(&self) -> &[u8] {
        match *self {
            Self::V1(_) => &[0u8; CSV_RTMR_REG_SIZE],
            Self::V2(tee_info) => &tee_info.rtmr1,
            Self::V3(tee_info) => &tee_info.rtmr1,
        }
    }

    /// Get rtmr2 field
    pub fn rtmr2(&self) -> &[u8] {
        match *self {
            Self::V1(_) => &[0u8; CSV_RTMR_REG_SIZE],
            Self::V2(tee_info) => &tee_info.rtmr2,
            Self::V3(tee_info) => &tee_info.rtmr2,
        }
    }

    /// Get rtmr3 field
    pub fn rtmr3(&self) -> &[u8] {
        match *self {
            Self::V1(_) => &[0u8; CSV_RTMR_REG_SIZE],
            Self::V2(tee_info) => &tee_info.rtmr3,
            Self::V3(tee_info) => &tee_info.rtmr3,
        }
    }

    /// Get rtmr4 field
    pub fn rtmr4(&self) -> &[u8] {
        match *self {
            Self::V1(_) => &[0u8; CSV_RTMR_REG_SIZE],
            Self::V2(tee_info) => &tee_info.rtmr4,
            Self::V3(tee_info) => &tee_info.rtmr4,
        }
    }

    /// Get host_data field. This is only present in the CSV3 attestation report.
    pub fn host_data(&self) -> &[u8] {
        match *self {
            Self::V1(_) | Self::V2(_) => &[0u8; CSV3_HOST_DATA_SIZE],
            Self::V3(tee_info) => &tee_info.host_data,
        }
    }
}

impl<'a> TryFrom<&'a TeeInfo<'a>> for Signature {
    type Error = std::io::Error;

    #[inline]
    fn try_from(value: &'a TeeInfo<'a>) -> Result<Self, std::io::Error> {
        match *value {
            TeeInfo::V1(v1) => {
                let sig = Vec::try_from(&v1.sig)?;
                Ok(Self {
                    sig,
                    id: None,
                    usage: Usage::PEK,
                    algo: None,
                })
            }
            TeeInfo::V2(v2) => {
                let sig = Vec::try_from(&v2.sig)?;
                Ok(Self {
                    sig,
                    id: None,
                    usage: Usage::PEK,
                    algo: None,
                })
            }
            TeeInfo::V3(v3) => {
                let sig = Vec::try_from(&v3.sig)?;
                Ok(Self {
                    sig,
                    id: None,
                    usage: Usage::PEK,
                    algo: None,
                })
            }
        }
    }
}

impl<'a> Verifiable for (&'a Certificate, &'a TeeInfo<'a>) {
    type Output = ();

    fn verify(self) -> Result<(), std::io::Error> {
        let (cert, tee_info) = self;
        let key: PublicKey = cert.try_into()?;
        let sig: Signature = tee_info.try_into()?;

        match *tee_info {
            TeeInfo::V1(v1) => key.verify(
                v1,
                &self.0.body.data.user_id[..self.0.body.data.uid_size as usize],
                &sig,
            ),
            TeeInfo::V2(v2) => key.verify(
                v2,
                &self.0.body.data.user_id[..self.0.body.data.uid_size as usize],
                &sig,
            ),
            TeeInfo::V3(v3) => key.verify(
                v3,
                &self.0.body.data.user_id[..self.0.body.data.uid_size as usize],
                &sig,
            ),
        }
    }
}

/// Data provieded by the guest owner for requesting an attestation report
/// from the HYGON Secure Processor.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeInfoV1 {
    /// Pubkey digest of the session used to secure communication between
    /// user/hypervisor and PSP.
    pub user_pubkey_digest: [u8; 32],
    /// The identifier of the VM custommized by the guest owner.
    pub vm_id: [u8; 16],
    /// The version info of the VM customized by the guest owner.
    pub vm_version: [u8; 16],
    #[serde(with = "BigArray")]
    /// The challenge data for the attestation.
    pub report_data: [u8; 64],
    /// The random nonce generated by user to protect struct TeeInfoSigner.
    pub mnonce: [u8; 16],
    /// The launch digest of the VM.
    pub measure: [u8; 32],
    /// The running policy of the VM.
    pub policy: GuestPolicy,
    /// The usage of the signature.
    pub sig_usage: u32,
    /// The algorithm of the signature.
    pub sig_algo: u32,
    /// The random nonce generated by firmware to tweak the attestation report.
    pub anonce: u32,
    /// The signature for the fields:
    ///   user_pubkey_digest,
    ///   vm_id,
    ///   vm_version,
    ///   report_data,
    ///   mnonce,
    ///   measure,
    ///   policy,
    pub sig: ecdsa::Signature,
}

// Compile-time check that the size is what is expected.
const_assert!(std::mem::size_of::<TeeInfoV1>() == 0x150);

impl Default for TeeInfoV1 {
    fn default() -> Self {
        Self {
            user_pubkey_digest: Default::default(),
            vm_id: Default::default(),
            vm_version: Default::default(),
            report_data: [0u8; 64],
            mnonce: Default::default(),
            measure: Default::default(),
            policy: Default::default(),
            sig_usage: Default::default(),
            sig_algo: Default::default(),
            anonce: Default::default(),
            sig: Default::default(),
        }
    }
}

impl codicon::Encoder<crate::Body> for TeeInfoV1 {
    type Error = std::io::Error;

    fn encode(&self, mut writer: impl Write, _: crate::Body) -> Result<(), std::io::Error> {
        writer.save(&self.user_pubkey_digest)?;
        writer.save(&self.vm_id)?;
        writer.save(&self.vm_version)?;
        writer.save(&self.report_data)?;
        writer.save(&self.mnonce)?;
        writer.save(&self.measure)?;
        writer.save(&self.policy)?;
        Ok(())
    }
}

/// Data provieded by the guest owner for requesting an extended attestation
/// report from the HYGON Secure Processor.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeInfoV2 {
    /// Pubkey digest of the session used to secure communication between
    /// user/hypervisor and PSP.
    pub user_pubkey_digest: [u8; 32],
    /// The identifier of the VM custommized by the guest owner.
    pub vm_id: [u8; 16],
    /// The version info of the VM customized by the guest owner.
    pub vm_version: [u8; 16],
    #[serde(with = "BigArray")]
    /// The challenge data for the attestation.
    pub report_data: [u8; 64],
    /// The random nonce generated by user to protect struct TeeInfoSigner.
    pub mnonce: [u8; 16],
    /// The launch digest of the VM.
    pub measure: [u8; 32],
    /// The running policy of the VM.
    pub policy: GuestPolicy,
    /// The usage of the signature.
    pub sig_usage: u32,
    /// The algorithm of the signature.
    pub sig_algo: u32,
    /// The version of the firmware's build.
    pub build: u32,
    /// The version of the VM's rtmr.
    pub rtmr_version: u16,
    /// A reserved field, for future use.
    pub reserved0: [u8; 14],
    /// The rtmr register 0, it's always equals to @measure field.
    pub rtmr0: [u8; CSV_RTMR_REG_SIZE],
    /// The rtmr register 1.
    pub rtmr1: [u8; CSV_RTMR_REG_SIZE],
    /// The rtmr register 2.
    pub rtmr2: [u8; CSV_RTMR_REG_SIZE],
    /// The rtmr register 3.
    pub rtmr3: [u8; CSV_RTMR_REG_SIZE],
    /// The rtmr register 4.
    pub rtmr4: [u8; CSV_RTMR_REG_SIZE],
    #[serde(with = "BigArray")]
    /// A reserved field, for future use.
    pub reserved1: [u8; 656],
    /// The signature for the fields:
    ///   user_pubkey_digest,
    ///   vm_id,
    ///   vm_version,
    ///   report_data,
    ///   mnonce,
    ///   measure,
    ///   policy,
    ///   sig_usage,
    ///   sig_algo,
    ///   build,
    ///   rtmr_version,
    ///   reserved0,
    ///   rtmr0,
    ///   rtmr1,
    ///   rtmr2,
    ///   rtmr3,
    ///   rtmr4,
    ///   reserved1,
    pub sig: ecdsa::Signature,
}

// Compile-time check that the size is what is expected.
const_assert!(std::mem::size_of::<TeeInfoV2>() == 0x490);

impl Default for TeeInfoV2 {
    fn default() -> Self {
        Self {
            user_pubkey_digest: Default::default(),
            vm_id: Default::default(),
            vm_version: Default::default(),
            report_data: [0u8; 64],
            mnonce: Default::default(),
            measure: Default::default(),
            policy: Default::default(),
            sig_usage: Default::default(),
            sig_algo: Default::default(),
            build: Default::default(),
            rtmr_version: Default::default(),
            reserved0: Default::default(),
            rtmr0: [0u8; CSV_RTMR_REG_SIZE],
            rtmr1: [0u8; CSV_RTMR_REG_SIZE],
            rtmr2: [0u8; CSV_RTMR_REG_SIZE],
            rtmr3: [0u8; CSV_RTMR_REG_SIZE],
            rtmr4: [0u8; CSV_RTMR_REG_SIZE],
            reserved1: [0u8; 656],
            sig: Default::default(),
        }
    }
}

impl codicon::Encoder<crate::Body> for TeeInfoV2 {
    type Error = std::io::Error;

    fn encode(&self, mut writer: impl Write, _: crate::Body) -> Result<(), std::io::Error> {
        writer.save(&self.user_pubkey_digest)?;
        writer.save(&self.vm_id)?;
        writer.save(&self.vm_version)?;
        writer.save(&self.report_data)?;
        writer.save(&self.mnonce)?;
        writer.save(&self.measure)?;
        writer.save(&self.policy)?;
        writer.save(&self.sig_usage)?;
        writer.save(&self.sig_algo)?;
        writer.save(&self.build)?;
        writer.save(&self.rtmr_version)?;
        writer.save(&self.reserved0)?;
        writer.save(&self.rtmr0)?;
        writer.save(&self.rtmr1)?;
        writer.save(&self.rtmr2)?;
        writer.save(&self.rtmr3)?;
        writer.save(&self.rtmr4)?;
        writer.save(&self.reserved1)?;
        Ok(())
    }
}

/// Data provieded by the guest owner for requesting a CSV3 attestation report
/// from the HYGON Secure Processor.
///
/// It has the same layout as [`TeeInfoV2`], except that the last 64 bytes of
/// `reserved1` are exposed as the `host_data` field.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeInfoV3 {
    /// Pubkey digest of the session used to secure communication between
    /// user/hypervisor and PSP.
    pub user_pubkey_digest: [u8; 32],
    /// The identifier of the VM custommized by the guest owner.
    pub vm_id: [u8; 16],
    /// The version info of the VM customized by the guest owner.
    pub vm_version: [u8; 16],
    #[serde(with = "BigArray")]
    /// The challenge data for the attestation.
    pub report_data: [u8; 64],
    /// The random nonce generated by user to protect struct TeeInfoSigner.
    pub mnonce: [u8; 16],
    /// The launch digest of the VM.
    pub measure: [u8; 32],
    /// The running policy of the VM.
    pub policy: GuestPolicy,
    /// The usage of the signature.
    pub sig_usage: u32,
    /// The algorithm of the signature.
    pub sig_algo: u32,
    /// The version of the firmware's build.
    pub build: u32,
    /// The version of the VM's rtmr.
    pub rtmr_version: u16,
    /// A reserved field, for future use.
    pub reserved0: [u8; 14],
    /// The rtmr register 0, it's always equals to @measure field.
    pub rtmr0: [u8; CSV_RTMR_REG_SIZE],
    /// The rtmr register 1.
    pub rtmr1: [u8; CSV_RTMR_REG_SIZE],
    /// The rtmr register 2.
    pub rtmr2: [u8; CSV_RTMR_REG_SIZE],
    /// The rtmr register 3.
    pub rtmr3: [u8; CSV_RTMR_REG_SIZE],
    /// The rtmr register 4.
    pub rtmr4: [u8; CSV_RTMR_REG_SIZE],
    #[serde(with = "BigArray")]
    /// A reserved field, for future use.
    pub reserved1: [u8; 592],
    #[serde(with = "BigArray")]
    /// The host supplied data.
    pub host_data: [u8; CSV3_HOST_DATA_SIZE],
    /// The signature for the fields:
    ///   user_pubkey_digest,
    ///   vm_id,
    ///   vm_version,
    ///   report_data,
    ///   mnonce,
    ///   measure,
    ///   policy,
    ///   sig_usage,
    ///   sig_algo,
    ///   build,
    ///   rtmr_version,
    ///   reserved0,
    ///   rtmr0,
    ///   rtmr1,
    ///   rtmr2,
    ///   rtmr3,
    ///   rtmr4,
    ///   reserved1,
    ///   host_data,
    pub sig: ecdsa::Signature,
}

// Compile-time check that the size is what is expected.
const_assert!(std::mem::size_of::<TeeInfoV3>() == 0x490);

impl Default for TeeInfoV3 {
    fn default() -> Self {
        Self {
            user_pubkey_digest: Default::default(),
            vm_id: Default::default(),
            vm_version: Default::default(),
            report_data: [0u8; 64],
            mnonce: Default::default(),
            measure: Default::default(),
            policy: Default::default(),
            sig_usage: Default::default(),
            sig_algo: Default::default(),
            build: Default::default(),
            rtmr_version: Default::default(),
            reserved0: Default::default(),
            rtmr0: [0u8; CSV_RTMR_REG_SIZE],
            rtmr1: [0u8; CSV_RTMR_REG_SIZE],
            rtmr2: [0u8; CSV_RTMR_REG_SIZE],
            rtmr3: [0u8; CSV_RTMR_REG_SIZE],
            rtmr4: [0u8; CSV_RTMR_REG_SIZE],
            reserved1: [0u8; 592],
            host_data: [0u8; CSV3_HOST_DATA_SIZE],
            sig: Default::default(),
        }
    }
}

impl codicon::Encoder<crate::Body> for TeeInfoV3 {
    type Error = std::io::Error;

    fn encode(&self, mut writer: impl Write, _: crate::Body) -> Result<(), std::io::Error> {
        writer.save(&self.user_pubkey_digest)?;
        writer.save(&self.vm_id)?;
        writer.save(&self.vm_version)?;
        writer.save(&self.report_data)?;
        writer.save(&self.mnonce)?;
        writer.save(&self.measure)?;
        writer.save(&self.policy)?;
        writer.save(&self.sig_usage)?;
        writer.save(&self.sig_algo)?;
        writer.save(&self.build)?;
        writer.save(&self.rtmr_version)?;
        writer.save(&self.reserved0)?;
        writer.save(&self.rtmr0)?;
        writer.save(&self.rtmr1)?;
        writer.save(&self.rtmr2)?;
        writer.save(&self.rtmr3)?;
        writer.save(&self.rtmr4)?;
        writer.save(&self.reserved1)?;
        writer.save(&self.host_data)?;
        Ok(())
    }
}

bitfield! {
    /// The firmware associates each guest with a guest policy that the guest owner provides. The
    /// firmware restricts what actions the hypervisor can take on the guest according to the guest policy.
    /// The policy also indicates the minimum firmware version to for the guest.
    ///
    /// The guest owner provides the guest policy to the firmware during launch. The firmware then binds
    /// the policy to the guest. The policy cannot be changed throughout the lifetime of the guest. The
    /// policy is also migrated with the guest and enforced by the destination platform firmware.
    ///
    /// | Bit(s) | Name           | Description                                                                                 >
    /// |--------|----------------|--------------------------------------------------------------------------------------------->
    /// | 0      | NODBG          | Debugging of the guest is disallowed when set                                               >
    /// | 1      | NOKS           | Sharing keys with other guests is disallowed when set                                       >
    /// | 2      | ES             | CSV2 is required when set                                                                   >
    /// | 3      | NOSEND         | Sending the guest to another platform is disallowed when set                                >
    /// | 4      | DOMAIN         | The guest must not be transmitted to another platform that is not in the domain when set.   >
    /// | 5      | CSV            | The guest must not be transmitted to another platform that is not CSV capable when set.     >
    /// | 6      | CSV3           | The guest must not be transmitted to another platform that is not CSV3 capable when set.    >
    /// | 7      | ASID_REUSE     | Sharing asids with other guests owned by same user is allowed when set                      >
    /// | 11:8   | HSK_VERSION    | The guest must not be transmitted to another platform with a lower HSK version.             >
    /// | 15:12  | CEK_VERSION    | The guest must not be transmitted to another platform with a lower CEK version.             >
    /// | 23:16  | API_MAJOR      | The guest must not be transmitted to another platform with a lower platform version.        >
    /// | 31:24  | API_MINOR      | The guest must not be transmitted to another platform with a lower platform version.        >
    #[repr(C)]
    #[derive(Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
    pub struct GuestPolicy(u32);
    impl Debug;
    pub nodbg, _: 0, 0;
    pub noks, _: 1, 1;
    pub es, _: 2, 2;
    pub nosend, _: 3, 3;
    pub domain, _: 4, 4;
    pub csv, _: 5, 5;
    pub csv3, _: 6, 6;
    pub asid_reuse, _: 7, 7;
    pub hsk_version, _: 11, 8;
    pub cek_version, _: 15, 12;
    pub api_major, _: 23, 16;
    pub api_minor, _: 31, 24;
}

impl GuestPolicy {
    #[allow(dead_code)]
    pub fn xor(&self, anonce: &u32) -> Self {
        Self(self.0 ^ anonce)
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeInfoSigner {
    #[serde(with = "BigArray")]
    pub pek_cert: [u8; 2084],
    #[serde(with = "BigArray")]
    pub sn: [u8; 64],
    pub reserved: [u8; 32],
    pub mac: [u8; 32],
}

fn xor_with_anonce(data: &mut [u8], anonce: &u32) -> Result<(), Error> {
    let mut anonce_array = [0u8; 4];
    anonce_array[..].copy_from_slice(&anonce.to_le_bytes());

    for (index, item) in data.iter_mut().enumerate() {
        *item ^= anonce_array[index % 4];
    }

    Ok(())
}

impl TeeInfoSigner {
    /// Verifies the signature evidence's hmac.
    pub fn verify(
        &mut self,
        input_mnonce: &[u8],
        mnonce: &[u8],
        anonce: &u32,
    ) -> Result<(), Error> {
        let mut real_mnonce = Vec::from(mnonce);
        xor_with_anonce(&mut real_mnonce, anonce)?;

        if real_mnonce != input_mnonce {
            return Err(Error::BadSignature);
        }

        let key = pkey::PKey::hmac(&real_mnonce)?;
        let mut sig = sign::Signer::new(MessageDigest::sm3(), &key)?;

        sig.update(&self.pek_cert)?;
        sig.update(&self.sn)?;
        sig.update(&self.reserved)?;

        if sig.sign_to_vec()? != self.mac {
            return Err(Error::BadSignature);
        }

        // restore pek cert and serial number.
        self.restore(anonce)?;

        Ok(())
    }

    fn restore(&mut self, anonce: &u32) -> Result<(), Error> {
        xor_with_anonce(&mut self.pek_cert, anonce)?;
        xor_with_anonce(&mut self.sn, anonce)?;

        // reset reserved to 0.
        self.reserved.fill(0);

        Ok(())
    }
}

impl Default for TeeInfoSigner {
    fn default() -> Self {
        Self {
            pek_cert: [0u8; 2084],
            sn: [0u8; 64],
            reserved: Default::default(),
            mac: Default::default(),
        }
    }
}

#[cfg(test)]
mod test {
    mod report_req {
        use crate::api::guest::types::ReportReq;
        #[test]
        pub fn test_new() {
            let data: [u8; 64] = [
                103, 198, 105, 115, 81, 255, 74, 236, 41, 205, 186, 171, 242, 251, 227, 70, 124,
                194, 84, 248, 27, 232, 231, 141, 118, 90, 46, 99, 51, 159, 201, 154, 102, 50, 13,
                183, 49, 88, 163, 90, 37, 93, 5, 23, 88, 233, 94, 212, 171, 178, 205, 198, 155,
                180, 84, 17, 14, 130, 116, 65, 33, 61, 220, 135,
            ];
            let mnonce: [u8; 16] = [
                112, 233, 62, 161, 65, 225, 252, 103, 62, 1, 126, 151, 234, 220, 107, 150,
            ];
            let hash: [u8; 32] = [
                19, 76, 8, 98, 33, 246, 247, 155, 28, 21, 245, 185, 118, 74, 162, 128, 82, 15, 160,
                233, 212, 130, 106, 177, 89, 6, 119, 243, 130, 21, 3, 153,
            ];
            let expected: ReportReq = ReportReq { data, mnonce, hash };

            let actual: ReportReq = ReportReq::new(Some(data), mnonce).unwrap();

            assert_eq!(expected, actual);
        }

        #[test]
        #[should_panic]
        pub fn test_new_error() {
            let data: [u8; 64] = [
                103, 198, 105, 115, 81, 255, 74, 236, 41, 205, 186, 171, 242, 251, 227, 70, 124,
                194, 84, 248, 27, 232, 231, 141, 118, 90, 46, 99, 51, 159, 201, 154, 102, 50, 13,
                183, 49, 88, 163, 90, 37, 93, 5, 23, 88, 233, 94, 212, 171, 178, 205, 198, 155,
                180, 84, 17, 14, 130, 116, 65, 33, 61, 220, 135,
            ];
            let mnonce: [u8; 16] = [
                112, 233, 62, 161, 65, 225, 252, 103, 62, 1, 126, 151, 234, 220, 107, 150,
            ];
            let wrong_mnonce: [u8; 16] = [
                0, 233, 62, 161, 65, 225, 252, 103, 62, 1, 126, 151, 234, 220, 107, 150,
            ];
            let hash: [u8; 32] = [
                19, 76, 8, 98, 33, 246, 247, 155, 28, 21, 245, 185, 118, 74, 162, 128, 82, 15, 160,
                233, 212, 130, 106, 177, 89, 6, 119, 243, 130, 21, 3, 153,
            ];
            let expected: ReportReq = ReportReq { data, mnonce, hash };

            let actual: ReportReq = ReportReq::new(Some(data), wrong_mnonce).unwrap();

            assert_eq!(expected, actual);
        }
    }
}
