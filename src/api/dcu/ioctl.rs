// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use iocuddle::{Group, Ioctl, WriteRead};

use std::marker::PhantomData;

pub enum CsvGuestIoctl {
    GetReport = 0x1,
    _Undefined,
}

const CSV: Group = Group::new(b'D');

pub const CSV_GET_REPORT: Ioctl<WriteRead, &GuestReportRequest> =
    unsafe { CSV.write_read(CsvGuestIoctl::GetReport as u8) };

/// The structure used for making guest report request to the PSP as a guest owner.
/// This struct is defined in the Linux kernel: drivers/virt/coco/csv-guest/csv-guest.h
#[repr(C)]
pub struct GuestReportRequest<'a> {
    /// Address of the data buffer with user REPORT_DATA included,
    /// and CSV_REPORT output from PSP to be saved.
    pub addr: u64,

    /// The page aligned length of the buffer start from [`req_rsp_addr`]
    pub len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> GuestReportRequest<'a> {
    /// Creates a new report request from the adresses provided.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            addr: data.as_ptr() as _,
            len: data.len() as _,
            _phantom: PhantomData,
        }
    }
}
