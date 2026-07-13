// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

//! A collection of type-safe ioctl implementations for the HYGON China Secure Virtualization
//! (CSV) platform. These ioctls are exported by the Linux kernel.

use crate::{
    api::launch::types::*,
    error::{Error, Indeterminate},
    impl_const_id,
};

use std::{
    marker::PhantomData,
    os::{raw::c_ulong, unix::io::AsRawFd},
};

use iocuddle::*;

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/kvm.h
impl_const_id! {
    /// The ioctl sub number
    pub Id => u32;

    Init = 0,
    EsInit = 1,
    LaunchStart<'_> = 2,
    LaunchUpdateData<'_> = 3,
    LaunchUpdateVmsa = 4,
    LaunchSecret<'_> = 5,
    LaunchMeasure<'_> = 6,
    LaunchFinish = 7,
    Attestation<'_> = 20,
    Csv3Init = 0xc0,
    Csv3LaunchEncryptData = 0xc1,
    Csv3LaunchEncryptVmcb = 0xc2,
    Csv3SetGuestPrivateMemory = 0xc8,
}

const KVM: Group = Group::new(0xAE);
const ENC_OP: Ioctl<WriteRead, &c_ulong> = unsafe { KVM.write_read(0xBA) };

// Note: the iocuddle::Ioctl::lie() constructor has been used here because
// KVM_MEMORY_ENCRYPT_OP ioctl was defined like this:
//
// _IOWR(KVMIO, 0xba, unsigned long)
//
// Instead of something like this:
//
// _IOWR(KVMIO, 0xba, struct kvm_sev_cmd)
//
// which would require extra work to wrap around the design decision for
// that ioctl.

/// Initialize the CSV platform context.
pub const INIT: Ioctl<WriteRead, &Command<Init>> = unsafe { ENC_OP.lie() };

/// Initialize the CSV2 platform context.
pub const ES_INIT: Ioctl<WriteRead, &Command<EsInit>> = unsafe { ENC_OP.lie() };

/// Initialize the CSV3 platform context.
pub const CSV3_INIT: Ioctl<WriteRead, &Command<Csv3Init>> = unsafe { ENC_OP.lie() };

/// Set guest private memory for CSV3.
pub const CSV3_SET_GUEST_PRIVATE_MEMORY: Ioctl<WriteRead, &Command<Csv3SetGuestPrivateMemory>> =
    unsafe { ENC_OP.lie() };

/// Encrypt guest data with its VEK for CSV3.
pub const CSV3_LAUNCH_ENCRYPT_DATA: Ioctl<WriteRead, &Command<Csv3LaunchEncryptData>> =
    unsafe { ENC_OP.lie() };

/// Encrypt the VMCB contents for CSV3.
pub const CSV3_LAUNCH_ENCRYPT_VMCB: Ioctl<WriteRead, &Command<Csv3LaunchEncryptVmcb>> =
    unsafe { ENC_OP.lie() };

/// Create encrypted guest context.
pub const LAUNCH_START: Ioctl<WriteRead, &Command<LaunchStart>> = unsafe { ENC_OP.lie() };

/// Encrypt guest data with its VEK.
pub const LAUNCH_UPDATE_DATA: Ioctl<WriteRead, &Command<LaunchUpdateData>> =
    unsafe { ENC_OP.lie() };

/// Encrypt the VMSA contents for CSV2.
pub const LAUNCH_UPDATE_VMSA: Ioctl<WriteRead, &Command<LaunchUpdateVmsa>> =
    unsafe { ENC_OP.lie() };

/// Inject a secret into the guest.
pub const LAUNCH_SECRET: Ioctl<WriteRead, &Command<LaunchSecret>> = unsafe { ENC_OP.lie() };

/// Get the guest's measurement.
pub const LAUNCH_MEASUREMENT: Ioctl<WriteRead, &Command<LaunchMeasure>> = unsafe { ENC_OP.lie() };

/// Complete the CSV launch flow and transition the guest into
/// the ready state.
pub const LAUNCH_FINISH: Ioctl<WriteRead, &Command<LaunchFinish>> = unsafe { ENC_OP.lie() };

pub const ATTESTATION: Ioctl<WriteRead, &Command<Attestation>> = unsafe { ENC_OP.lie() };

/// Corresponds to the `KVM_MEMORY_ENCRYPT_REG_REGION` ioctl
pub const ENC_REG_REGION: Ioctl<Write, &KvmEncRegion> =
    unsafe { KVM.read::<KvmEncRegion>(0xBB).lie() };

/// Corresponds to the kernel struct `kvm_enc_region`
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct KvmEncRegion<'a> {
    addr: u64,
    size: u64,
    phantom: PhantomData<&'a [u8]>,
}

impl<'a> KvmEncRegion<'a> {
    /// Create a new `KvmEncRegion` referencing some memory assigned to the virtual machine.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            addr: data.as_ptr() as _,
            size: data.len() as _,
            phantom: PhantomData,
        }
    }

    /// Register the encrypted memory region to a virtual machine
    pub fn register(&mut self, vm_fd: &mut impl AsRawFd) -> std::io::Result<std::os::raw::c_uint> {
        ENC_REG_REGION.ioctl(vm_fd, self)
    }
}

/// A generic CSV command
#[repr(C)]
pub struct Command<'a, T: Id> {
    code: u32,
    data: u64,
    error: u32,
    csv_fd: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: Id> Command<'a, T> {
    /// create the command from a mutable subcommand
    pub fn from_mut(csv: &'a mut impl AsRawFd, subcmd: &'a mut T) -> Self {
        Self {
            code: T::ID,
            data: subcmd as *mut T as _,
            error: 0,
            csv_fd: csv.as_raw_fd() as _,
            _phantom: PhantomData,
        }
    }

    /// create the command from a subcommand reference
    pub fn from(csv: &'a mut impl AsRawFd, subcmd: &'a T) -> Self {
        Self {
            code: T::ID,
            data: subcmd as *const T as _,
            error: 0,
            csv_fd: csv.as_raw_fd() as _,
            _phantom: PhantomData,
        }
    }

    /// encapsulate a `std::io::Error` in an `Indeterminate<Error>`
    pub fn encapsulate(&self, err: std::io::Error) -> Indeterminate<Error> {
        match self.error {
            0 => Indeterminate::<Error>::from(err),
            _ => Indeterminate::<Error>::from(self.error),
        }
    }
}
