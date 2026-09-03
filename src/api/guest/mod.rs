// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::error::*;
mod ioctl;
pub use ioctl::*;
mod types;
use rand::Rng;
use std::fs::{File, OpenOptions};
pub use types::*;

pub mod rtmr;
pub use rtmr::*;

/// A handle to the CSV guest device.
pub struct CsvGuest(File);

impl CsvGuest {
    /// Generate a handle to the CSV guest platform via `/dev/csv-guest`.
    pub fn open() -> std::io::Result<CsvGuest> {
        let file = OpenOptions::new().read(true).open("/dev/csv-guest")?;
        Ok(CsvGuest(file))
    }

    /// Requests an legacy attestation report (i.e. AttestationReportV1) from
    /// the HYGON Secure Processor.
    ///
    /// Hygon CSV1,CSV2 only support legacy attestation report.
    /// Hygon CSV3 supports legacy attestation report, and supports extended
    /// attestation report (i.e. AttestationReportV2) if the firmware has a
    /// build version >= 2337.
    pub fn get_report(
        &mut self,
        data: Option<[u8; 64]>,
        mnonce: Option<[u8; 16]>,
    ) -> Result<AttestationReportWrapper, Error> {
        let mut mnonce_value = [0u8; 16];
        if let Some(mnonce) = mnonce {
            mnonce_value = mnonce;
        } else {
            let mut rng = rand::thread_rng();
            for element in &mut mnonce_value {
                *element = rng.gen();
            }
        }

        let report_request = ReportReq::new(data, mnonce_value)?;

        let mut report_response = AttestationReportV1::default();

        // Convert ReportReq to bytes
        let request_bytes: &[u8] = unsafe {
            let req_ptr = &report_request as *const ReportReq as *const u8;
            std::slice::from_raw_parts(req_ptr, std::mem::size_of::<ReportReq>())
        };

        let response_bytes: &mut [u8] = unsafe {
            let rsp_ptr = &mut report_response as *mut AttestationReportV1 as *mut u8;
            std::slice::from_raw_parts_mut(rsp_ptr, std::mem::size_of::<AttestationReportV1>())
        };

        // Copy bytes from report_request to report_response
        response_bytes[..request_bytes.len()].copy_from_slice(request_bytes);

        let mut guest_report_request = GuestReportRequest::new(response_bytes);

        CSV_GET_REPORT.ioctl(&mut self.0, &mut guest_report_request)?;

        report_response.signer.verify(
            &mnonce_value,
            &report_response.tee_info.mnonce,
            &report_response.tee_info.anonce,
        )?;

        Ok(AttestationReportWrapper::new([0u8; 16], 0, response_bytes))
    }

    /// Requests an extended attestation report (i.e. AttestationReportV2) from
    /// the HYGON Secure Processor.
    ///
    /// Hygon CSV1,CSV2 only support legacy attestation report.
    /// Hygon CSV3 supports legacy attestation report, and supports extended
    /// attestation report if the firmware has a build version >= 2337.
    ///
    /// If extended attestation report is not supported, then request legacy
    /// attestation report.
    ///
    /// When the [`CSV_ATTESTATION_FLAG_REPORT_EXT_V3`] flag is set, the CSV3
    /// attestation report (i.e. AttestationReportV3) is requested. However, the
    /// CSV3 report format requires a firmware build version >=
    /// [`CSV3_ATTESTATION_MIN_BUILD`]. Therefore we first request a V2 report to
    /// inspect the build version, and only then request the V3 report if the
    /// requirement is met; otherwise we fall back to the V2 report.
    pub fn get_report_ext(
        &mut self,
        data: Option<[u8; 64]>,
        mnonce: Option<[u8; 16]>,
        flags: u32,
    ) -> Result<AttestationReportWrapper, Error> {
        if !self.check_attestation_report_v2_supported() {
            return self.get_report(data, mnonce);
        }

        if flags == 0 {
            // If flags is 0, generate AttestationReportV1.
            return self.get_report(data, mnonce);
        }

        let mut mnonce_value = [0u8; 16];
        if let Some(mnonce) = mnonce {
            mnonce_value = mnonce;
        } else {
            let mut rng = rand::thread_rng();
            for element in &mut mnonce_value {
                *element = rng.gen();
            }
        }

        if flags & CSV_ATTESTATION_FLAG_REPORT_EXT_V3 != 0 {
            // Probe the firmware build version with a V2 report first.
            let v2_wrapper =
                self.request_report_ext(data, mnonce_value, CSV_ATTESTATION_FLAG_REPORT_EXT)?;
            let build = match AttestationReport::try_from(&v2_wrapper) {
                Ok(AttestationReport::V2(report)) => report.tee_info.build,
                _ => return Ok(v2_wrapper),
            };

            if build >= CSV3_ATTESTATION_MIN_BUILD {
                self.request_report_ext(data, mnonce_value, flags)
            } else {
                Ok(v2_wrapper)
            }
        } else {
            self.request_report_ext(data, mnonce_value, flags)
        }
    }

    /// Issue an extended attestation report request with the given flags and
    /// return the raw response wrapped in an [`AttestationReportWrapper`].
    ///
    /// The response buffer type is chosen based on `flags`: a V3 request uses
    /// [`AttestationReportV3`], while any other extended request uses
    /// [`AttestationReportV2`].
    fn request_report_ext(
        &mut self,
        data: Option<[u8; 64]>,
        mnonce_value: [u8; 16],
        flags: u32,
    ) -> Result<AttestationReportWrapper, Error> {
        if flags & CSV_ATTESTATION_FLAG_REPORT_EXT_V3 != 0 {
            self.request_report_ext_as::<AttestationReportV3>(data, mnonce_value, flags)
        } else {
            self.request_report_ext_as::<AttestationReportV2>(data, mnonce_value, flags)
        }
    }

    /// Issue an extended attestation report request whose response buffer is of
    /// type `R`, returning the raw response wrapped in an
    /// [`AttestationReportWrapper`].
    fn request_report_ext_as<R: ExtReportResponse>(
        &mut self,
        data: Option<[u8; 64]>,
        mnonce_value: [u8; 16],
        flags: u32,
    ) -> Result<AttestationReportWrapper, Error> {
        let report_request = ReportReqExt::new(data, mnonce_value, flags)?;

        let mut report_response = R::default();

        // Convert ReportReqExt to bytes
        let request_bytes: &[u8] = unsafe {
            let req_ptr = &report_request as *const ReportReqExt as *const u8;
            std::slice::from_raw_parts(req_ptr, std::mem::size_of::<ReportReqExt>())
        };

        let response_bytes: &mut [u8] = unsafe {
            let rsp_ptr = &mut report_response as *mut R as *mut u8;
            std::slice::from_raw_parts_mut(rsp_ptr, std::mem::size_of::<R>())
        };

        // Copy bytes from report_request_ext to report_response_ext
        response_bytes[..request_bytes.len()].copy_from_slice(request_bytes);

        let mut guest_report_request = GuestReportRequest::new(response_bytes);

        CSV_GET_REPORT.ioctl(&mut self.0, &mut guest_report_request)?;

        report_response.verify_signer(&mnonce_value)?;

        Ok(AttestationReportWrapper::new(
            ATTESTATION_EXT_MAGIC,
            flags,
            response_bytes,
        ))
    }

    /// Request rtmr_status
    pub fn req_rtmr_status(&mut self) -> Result<CsvGuestUserRtmrStatus, std::io::Error> {
        let mut rtmr_status = CsvGuestUserRtmrStatus::new();

        let rtmr_status_bytes: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                &mut rtmr_status as *mut _ as *mut u8,
                std::mem::size_of::<CsvGuestUserRtmrStatus>(),
            )
        };

        let mut rtmr_request =
            GuestRtmrRequest::new(rtmr_status_bytes, CsvGuestUserRtmrSubcmd::Status);

        match CSV_RTMR_REQ.ioctl(&mut self.0, &mut rtmr_request) {
            Ok(return_code) => {
                if return_code == 0 {
                    let fw_error_code = rtmr_request.get_fw_error_code();
                    if fw_error_code == 0 {
                        Ok(rtmr_status)
                    } else {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("rtmr_status fail, fw_err: {}", fw_error_code),
                        ))
                    }
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("rtmr_status fail, rc: {}", return_code),
                    ))
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Request rtmr_start
    pub fn req_rtmr_start(
        &mut self,
        version: u16,
    ) -> Result<CsvGuestUserRtmrStart, std::io::Error> {
        let mut rtmr_start = CsvGuestUserRtmrStart::new(version);

        let rtmr_start_bytes: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                &mut rtmr_start as *mut _ as *mut u8,
                std::mem::size_of::<CsvGuestUserRtmrStart>(),
            )
        };

        let mut rtmr_request =
            GuestRtmrRequest::new(rtmr_start_bytes, CsvGuestUserRtmrSubcmd::Start);

        match CSV_RTMR_REQ.ioctl(&mut self.0, &mut rtmr_request) {
            Ok(return_code) => {
                if return_code == 0 {
                    let fw_error_code = rtmr_request.get_fw_error_code();
                    if fw_error_code == 0 {
                        Ok(rtmr_start)
                    } else {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("rtmr_start fail, fw_err: {}", fw_error_code),
                        ))
                    }
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("rtmr_start fail, rc: {}", return_code),
                    ))
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Request rtmr_read
    pub fn req_rtmr_read(
        &mut self,
        bitmap: u32,
    ) -> Result<(Box<[u8]>, &mut CsvGuestUserRtmrRead), std::io::Error> {
        let mut num_regs: usize = 0;

        for i in 0..CSV_RTMR_REG_NUM {
            if bitmap & (1 << i) != 0 {
                num_regs += 1;
            }
        }

        let (mut _buffer, rtmr_read) =
            CsvGuestUserRtmrRead::allocate_with_capacity(bitmap, num_regs);

        let mut rtmr_request =
            GuestRtmrRequest::new(_buffer.as_ref(), CsvGuestUserRtmrSubcmd::Read);

        match CSV_RTMR_REQ.ioctl(&mut self.0, &mut rtmr_request) {
            Ok(return_code) => {
                if return_code == 0 {
                    let fw_error_code = rtmr_request.get_fw_error_code();
                    if fw_error_code == 0 {
                        Ok((_buffer, rtmr_read))
                    } else {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("rtmr_read fail, fw_err: {}", fw_error_code),
                        ))
                    }
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("rtmr_read fail, rc: {}", return_code),
                    ))
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Request rtmr_extend
    pub fn req_rtmr_extend(
        &mut self,
        index: u8,
        data: &[u8],
    ) -> Result<CsvGuestUserRtmrExtend, std::io::Error> {
        let mut rtmr_extend = CsvGuestUserRtmrExtend::new(index, data)?;

        let rtmr_extend_bytes: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                &mut rtmr_extend as *mut _ as *mut u8,
                std::mem::size_of::<CsvGuestUserRtmrExtend>(),
            )
        };

        let mut rtmr_request =
            GuestRtmrRequest::new(rtmr_extend_bytes, CsvGuestUserRtmrSubcmd::Extend);

        match CSV_RTMR_REQ.ioctl(&mut self.0, &mut rtmr_request) {
            Ok(return_code) => {
                if return_code == 0 {
                    let fw_error_code = rtmr_request.get_fw_error_code();
                    if fw_error_code == 0 {
                        Ok(rtmr_extend)
                    } else {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("rtmr_extend fail, fw_err: {}", fw_error_code),
                        ))
                    }
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("rtmr_extend fail, rc: {}", return_code),
                    ))
                }
            }
            Err(err) => Err(err),
        }
    }

    /// Query if the rtmr is supported.
    /// The rtmr_status request will succeed when rtmr is supported.
    pub fn check_rtmr_supported(&mut self) -> bool {
        match self.req_rtmr_status() {
            Ok(_) => true,
            Err(err) => {
                println!("error: {}", err);
                false
            }
        }
    }

    /// Query if AttestationReportV2 is supported. It's supported when rtmr is
    /// supported.
    pub fn check_attestation_report_v2_supported(&mut self) -> bool {
        self.check_rtmr_supported()
    }
}

/// Common interface shared by [`AttestationReportV2`] and
/// [`AttestationReportV3`] so they can be used interchangeably as the response
/// buffer of an extended attestation report request.
trait ExtReportResponse: Default + Sized {
    /// Verify the signer HMAC of the report using the given guest-provided
    /// mnonce. The signer and mnonce fields share the same layout in both
    /// [`AttestationReportV2`] and [`AttestationReportV3`], so the verification
    /// logic is identical for the two.
    fn verify_signer(&mut self, mnonce_value: &[u8]) -> Result<(), Error>;
}

macro_rules! impl_ext_report_response {
    ($($report:ty),+ $(,)?) => {
        $(
            impl ExtReportResponse for $report {
                fn verify_signer(&mut self, mnonce_value: &[u8]) -> Result<(), Error> {
                    self.signer.verify(mnonce_value, &self.tee_info.mnonce, &0)
                }
            }
        )+
    };
}

impl_ext_report_response!(AttestationReportV2, AttestationReportV3);
