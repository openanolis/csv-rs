// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! A collection of type-safe ioctl implementations for the Hygon China Secure Virtualization
//! (CSV) platform. These ioctls are exported by the Linux kernel.

use super::types::*;
use crate::impl_const_id;
use iocuddle::{Group, Ioctl, WriteRead};
use std::marker::PhantomData;

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/psp-sev.h
impl_const_id! {
    pub Id => u32;

    PlatformReset = 0x0,
    PlatformStatus = 0x1,
    PekGen = 0x2,
    PekCsr<'_> = 0x3,
    PdhGen = 0x4,
    PdhCertExport<'_> = 0x5,
    PekCertImport<'_> = 0x6,
    GetId<'_> = 0x8, /* GET_ID2 is 0x8, the deprecated GET_ID ioctl is 0x7 */
}

const CSV: Group = Group::new(b'S');

/// Resets the CSV platform's persistent state.
pub const PLATFORM_RESET: Ioctl<WriteRead, &Command<PlatformReset>> = unsafe { CSV.write_read(0) };

/// Gathers a status report from the CSV firmware.
pub const PLATFORM_STATUS: Ioctl<WriteRead, &Command<PlatformStatus>> =
    unsafe { CSV.write_read(0) };

/// Generate a new Platform Endorsement Key (PEK).
pub const PEK_GEN: Ioctl<WriteRead, &Command<PekGen>> = unsafe { CSV.write_read(0) };

/// Take ownership of the platform.
pub const PEK_CSR: Ioctl<WriteRead, &Command<PekCsr<'_>>> = unsafe { CSV.write_read(0) };

/// (Re)generate the Platform Diffie-Hellman (PDH).
pub const PDH_GEN: Ioctl<WriteRead, &Command<PdhGen>> = unsafe { CSV.write_read(0) };

/// Retrieve the PDH and the platform certificate chain.
pub const PDH_CERT_EXPORT: Ioctl<WriteRead, &Command<PdhCertExport<'_>>> =
    unsafe { CSV.write_read(0) };

/// Join the platform to the domain.
pub const PEK_CERT_IMPORT: Ioctl<WriteRead, &Command<PekCertImport<'_>>> =
    unsafe { CSV.write_read(0) };

/// Get the CPU's unique ID that can be used for getting a certificate for the CEK public key.
pub const GET_ID: Ioctl<WriteRead, &Command<GetId<'_>>> = unsafe { CSV.write_read(0) };

/// The Rust-flavored, FFI-friendly version of `struct sev_issue_cmd` which is
/// used to pass arguments to the CSV ioctl implementation.
///
/// This struct is defined in the Linux kernel: include/uapi/linux/psp-sev.h
#[repr(C, packed)]
pub struct Command<'a, T: Id> {
    pub code: u32,
    pub data: u64,
    pub error: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: Id> Command<'a, T> {
    /// Create an CSV command with the expectation that the host platform/kernel will write to
    /// the caller's address space either to the data held in the `Command.subcmd` field or some
    /// other region specified by the `Command.subcmd` field.
    pub fn from_mut(subcmd: &'a mut T) -> Self {
        Command {
            code: T::ID,
            data: subcmd as *mut T as u64,
            error: 0,
            _phantom: PhantomData,
        }
    }

    /// Create an CSV command with the expectation that the host platform/kernel *WILL NOT* mutate
    /// the caller's address space in its response. Note: this does not actually prevent the host
    /// platform/kernel from writing to the caller's address space if it wants to. This is primarily
    /// a semantic tool for programming against the CSV ioctl API.
    pub fn from(subcmd: &'a T) -> Self {
        Command {
            code: T::ID,
            data: subcmd as *const T as u64,
            error: 0,
            _phantom: PhantomData,
        }
    }
}
