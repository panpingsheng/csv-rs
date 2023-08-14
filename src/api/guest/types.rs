// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::error::*;

use openssl::{
    hash::{Hasher, MessageDigest},
    pkey,
    sign,
};

use static_assertions::const_assert;

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

/// The response from the PSP containing the generated attestation report.
/// 
/// The Report is padded to exactly 4096 Bytes to make sure the page size
/// matches.
#[repr(C)]
pub struct ReportRsp {
    /// The attestation report generated by the firmware.
    pub report: AttestationReport,
    /// The evidence to varify the attestation report's signature.
    pub signer:  ReportSigner,
    /// Padding bits to meet the memory page alignment.
    reserved: [u8; 4096
        - (std::mem::size_of::<AttestationReport>()
            + std::mem::size_of::<ReportSigner>())],
}

// Compile-time check that the size is what is expected.
const_assert!(std::mem::size_of::<ReportRsp>() == 4096);

impl Default for ReportRsp {
    fn default() -> Self {
        Self {
            report: Default::default(),
            signer: Default::default(),
            reserved: [0u8; 4096
            - (std::mem::size_of::<AttestationReport>()
                + std::mem::size_of::<ReportSigner>())],
        }
    }
}

/// Data provieded by the guest owner for requesting an attestation report
/// from the HYGON Secure Processor.
#[repr(C)]
pub struct AttestationReport {
    pub user_pubkey_digest: [u8; 32],
    pub vm_id: [u8; 16],
    pub vm_version: [u8; 16],
    pub report_data: [u8; 64],
    pub mnonce: [u8; 16],
    pub measure: [u8; 32],
    pub policy: u32,
    pub sig_usage: u32,
    pub sig_algo: u32,
    pub anonce: u32,
    pub sig: [u8; 144],
}

impl Default for AttestationReport {
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
            sig: [0u8; 144],
        }
    }
}

#[repr(C)]
pub struct ReportSigner {
    pub pek_cert: [u8; 2084],
    pub sn: [u8; 64],
    pub reserved: [u8; 32],
    pub mac: [u8; 32],
}

impl ReportSigner {
    /// Verifies the signature evidence's hmac.
    pub fn verify(&mut self, mnonce: &[u8], anonce: &u32) -> Result<(), Error> {
        let real_mnonce = self.recover_mnonce(mnonce, anonce);
        let key = pkey::PKey::hmac(&real_mnonce)?;
        let mut sig = sign::Signer::new(MessageDigest::sm3(), &key)?;

        sig.update(&self.pek_cert)?;
        sig.update(&self.sn)?;
        sig.update(&self.reserved)?;

        if sig.sign_to_vec()? != self.mac {
            return Err(Error::BadSignature);
        }

        // reset reserved to 0.
        self.reserved.fill(0);

        Ok(())
    }

    fn recover_mnonce(&self, mnonce: &[u8], anonce: &u32) -> Vec<u8> {
        let mut real_mnonce: Vec<u8> = Vec::with_capacity(mnonce.len());

        let mut anonce_array = [0u8; 4];
        anonce_array[..].copy_from_slice(&anonce.to_le_bytes());

        for (index, item) in mnonce.iter().enumerate() {
            real_mnonce.push(item ^ anonce_array[index % 4]);
        }

        real_mnonce
    }
}

impl Default for ReportSigner {
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
            let expected: ReportReq = ReportReq {
                data,
                mnonce,
                hash,
            };

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
            let expected: ReportReq = ReportReq {
                data,
                mnonce,
                hash,
            };

            let actual: ReportReq = ReportReq::new(Some(data), wrong_mnonce).unwrap();

            assert_eq!(expected, actual);
        }
    }
}
