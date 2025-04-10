// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::error::*;
mod ioctl;
pub use ioctl::*;
mod types;
pub use types::*;
use rand::Rng;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::io::AsRawFd;
use libc::{ioctl, open, O_CLOEXEC, O_RDWR};
use std::fs;

const MKFD_IOCTL_BASE: u8 = b'M';
const MKFD_IOC_SECURITY_ATTESTATION: u64 = libc::_IOWR!(MKFD_IOCTL_BASE, 0x17, MkfdIoctlSecurityAttestationArgs);

fn topology_sysfs_get_gpu_id(sysfs_node_id: u32) -> io::Result<u32> {
    let path = format!("/sys/devices/virtual/kfd/kfd/topology/nodes/{}/gpu_id", sysfs_node_id);
    let mut contents = String::new();
    File::open(&path)?.read_to_string(&mut contents)?;
    contents.trim().parse::<u32>().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Failed to parse GPU ID"))
}

fn num_subdirs(dirpath: &str, prefix: &str) -> usize {
    fs::read_dir(dirpath)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    let name = entry.file_name().to_string_lossy();
                    !(name == "." || name == "..") && (prefix.is_empty() || name.starts_with(prefix))
                })
                .count()
        })
        .unwrap_or(0)
}

fn hex_dump(addr: &[u8]) {
    addr.chunks(16).for_each(|chunk| {
        for byte in chunk {
            print!("{:02X} ", byte);
        }
        println!();
    });
}

/// A handle to the CSV guest device.
pub struct DcuGuest(File);

impl DcuGuest {
    /// Generate a handle to the CSV guest platform via `/dev/csv-guest`.
    pub fn open() -> std::io::Result<DcuGuest> {
        OpenOptions::new().read(true).open("/dev/csv-guest").map(DcuGuest)
    }

    /// Requests an attestation report from the HYGON Secure Processor.
    pub fn get_report(
        &mut self,
        data: Option<[u8; 64]>,
        mnonce: Option<[u8; 16]>,
    ) -> Result<AttestationReport, Error> {
        let mut mnonce_value = mnonce.unwrap_or_else(|| {
            let mut rng = rand::thread_rng();
            let mut nonce = [0u8; 16];
            nonce.iter_mut().for_each(|byte| *byte = rng.gen());
            nonce
        });

        let fd = unsafe { open("/dev/mkfd\0".as_ptr() as *const i8, O_RDWR | O_CLOEXEC) };
        if fd == -1 {
            return Err(std::io::Error::last_os_error().into());
        }

        let num_node = num_subdirs("/sys/devices/virtual/kfd/kfd/topology/nodes", "");
        for node in 0..num_node {
            if let Ok(gpu_id) = topology_sysfs_get_gpu_id(node as u32) {
                let mut args = MkfdIoctlSecurityAttestationArgs {
                    gpu_id,
                    version: 1,
                    request_data: std::ptr::null_mut(),
                    request_size: PAGE_SIZE as u64,
                    response_data: std::ptr::null_mut(),
                    response_size: PAGE_SIZE as u64,
                    fw_err: 0,
                };

                let report_request = ReportReq::new(mnonce_value)?;
                args.request_data = unsafe {
                    let ptr = libc::malloc(std::mem::size_of::<ReportReq>()) as *mut ReportReq;
                    if ptr.is_null() {
                        return Err(io::Error::new(io::ErrorKind::Other, "Failed to allocate memory for request_data").into());
                    }
                    ptr.write(report_request);
                    ptr as *mut _
                };

                args.response_data = unsafe {
                    let ptr = libc::malloc(PAGE_SIZE);
                    if ptr.is_null() {
                        return Err(io::Error::new(io::ErrorKind::Other, "Failed to allocate memory for response_data").into());
                    }
                    libc::memset(ptr, 0, PAGE_SIZE);
                    ptr
                };

                if let Err(e) = perform_ioctl(fd, &mut args) {
                    eprintln!("IOCTL failed: {}", e);
                    unsafe {
                        libc::free(args.request_data);
                        libc::free(args.response_data);
                    }
                    continue;
                }

                // Process response...
                unsafe {
                    libc::free(args.request_data);
                    libc::free(args.response_data);
                }
            }
        }

        unsafe { libc::close(fd) };
        Ok(AttestationReport::default()) // Replace with actual processing of response
    }
}
