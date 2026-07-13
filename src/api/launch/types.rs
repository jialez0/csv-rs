// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

//! Types for interacting with the KVM CSV guest management API.

use crate::{
    api::launch::{AttestationReport, Header, Measurement, Policy, Session},
    certs::csv::Certificate,
};

use std::{
    marker::PhantomData,
    mem::{size_of_val, MaybeUninit},
};

/// Initialize the CSV platform context.
#[repr(C)]
pub struct Init;

/// Initialize the CSV2 platform context.
#[repr(C)]
pub struct EsInit;

/// Initialize the CSV3 platform context.
#[repr(C)]
pub struct Csv3Init {
    /// NUMA node mask for memory allocation
    pub nodemask: u64,
}

impl Csv3Init {
    /// Create a new CSV3 initialization structure.
    ///
    /// # Arguments
    /// * `nodemask` - NUMA node mask for memory allocation. Set to 0 for default behavior.
    pub fn new(nodemask: u64) -> Self {
        Self { nodemask }
    }
}

/// Set guest private memory for CSV3.
/// Corresponds to `KVM_CSV3_SET_GUEST_PRIVATE_MEMORY`.
#[repr(C)]
pub struct Csv3SetGuestPrivateMemory;

/// Encrypt guest data with its VEK for CSV3.
/// Corresponds to `KVM_CSV3_LAUNCH_ENCRYPT_DATA` (`struct kvm_csv3_launch_encrypt_data`).
#[repr(C)]
pub struct Csv3LaunchEncryptData {
    /// Guest physical address of the memory to encrypt.
    pub gpa: u64,
    /// Userspace address of the data to encrypt.
    pub uaddr: u64,
    /// Length of the data to encrypt.
    pub len: u32,
}

/// Encrypt the VMCB contents for CSV3.
/// Corresponds to `KVM_CSV3_LAUNCH_ENCRYPT_VMCB`.
#[repr(C)]
pub struct Csv3LaunchEncryptVmcb;

#[repr(transparent)]
pub struct Handle(u32);

impl From<LaunchStart<'_>> for Handle {
    fn from(ls: LaunchStart) -> Self {
        ls.handle
    }
}

/// Initiate CSV launch flow.
#[repr(C)]
pub struct LaunchStart<'a> {
    handle: Handle,
    policy: Policy,
    dh_addr: u64,
    dh_len: u32,
    session_addr: u64,
    session_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> LaunchStart<'a> {
    pub fn new(policy: &'a Policy, dh: &'a Certificate, session: &'a Session) -> Self {
        Self {
            handle: Handle(0), /* platform will generate one for us */
            policy: *policy,
            dh_addr: dh as *const _ as _,
            dh_len: size_of_val(dh) as _,
            session_addr: session as *const _ as _,
            session_len: size_of_val(session) as _,
            _phantom: PhantomData,
        }
    }

    pub fn with_policy_only(policy: &'a Policy) -> Self {
        Self {
            handle: Handle(0), /* platform will generate one for us */
            policy: *policy,
            dh_addr: 0,
            dh_len: 0,
            session_addr: 0,
            session_len: 0,
            _phantom: PhantomData,
        }
    }
}

/// Encrypt guest data with its VEK.
#[repr(C)]
pub struct LaunchUpdateData<'a> {
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> LaunchUpdateData<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            addr: data.as_ptr() as _,
            len: data.len() as _,
            _phantom: PhantomData,
        }
    }
}

/// Update VMSA for setting up vCPUs on CSV2.
#[repr(C)]
pub struct LaunchUpdateVmsa;

impl LaunchUpdateVmsa {
    pub fn new() -> Self {
        Self
    }
}

/// Inject a secret into the guest.
#[repr(C)]
pub struct LaunchSecret<'a> {
    hdr_addr: u64,
    hdr_len: u32,
    guest_addr: u64,
    guest_len: u32,
    trans_addr: u64,
    trans_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> LaunchSecret<'a> {
    pub fn new(header: &'a Header, guest: usize, trans: &'a [u8]) -> Self {
        Self {
            hdr_addr: header as *const _ as _,
            hdr_len: size_of_val(header) as _,
            guest_addr: guest as _,
            guest_len: trans.len() as _,
            trans_addr: trans.as_ptr() as _,
            trans_len: trans.len() as _,
            _phantom: PhantomData,
        }
    }
}

/// Get the guest's measurement.
#[repr(C)]
pub struct LaunchMeasure<'a> {
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a Measurement>,
}

impl<'a> LaunchMeasure<'a> {
    pub fn new(measurement: &'a mut MaybeUninit<Measurement>) -> Self {
        Self {
            addr: measurement.as_mut_ptr() as _,
            len: size_of_val(measurement) as _,
            _phantom: PhantomData,
        }
    }
}

/// Complete the CSV launch flow and transition guest into
/// ready state.
#[repr(C)]
pub struct LaunchFinish;

#[repr(C)]
pub struct Attestation<'a> {
    mnonce: [u8; 16],
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a AttestationReport>,
}

impl<'a> Attestation<'a> {
    pub fn new(ar: &'a mut MaybeUninit<AttestationReport>, mnonce: [u8; 16]) -> Self {
        Self {
            mnonce,
            addr: ar.as_mut_ptr() as _,
            len: size_of_val(ar) as _,
            _phantom: PhantomData,
        }
    }
}
