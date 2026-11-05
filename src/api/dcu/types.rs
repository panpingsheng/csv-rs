// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{
    certs::{csv::Certificate, Usage, Verifiable},
    crypto::{sig::ecdsa, PublicKey, Signature},
    util::*,
};

use hex::encode;
use log::*;
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::io::Write;

/// Serde-only view of [`Body`] that accepts both report-body shapes:
/// - legacy: 128-byte `reserved`, no `ccmode` (old producers also named
///   `sig_algo`/`sig_usage` after the opposite firmware offsets);
/// - current: `ccmode` + 124-byte `reserved`.
///
/// The shape, not `version`, selects the decoding branch: during a rolling
/// upgrade a legacy producer may emit a version 2 body and a current producer
/// may emit a legacy body. `version` only decides whether `ccmode` is exposed.
#[derive(Deserialize)]
struct BodyRepr {
    version: u32,
    chip_id: [u8; 16],
    #[serde(with = "serde_bytes")]
    user_data: [u8; 64],
    measure: [u8; 32],
    #[serde(default)]
    ccmode: Option<u32>,
    #[serde(with = "serde_bytes")]
    reserved: Vec<u8>,
    sig_algo: u32,
    sig_usage: u32,
}

/// A structure representing the body of an attestation report.
/// This is marked with `repr(C)` for C compatibility and can be serialized/deserialized.
///
/// Deserialization accepts both report-body shapes (see [`BodyRepr`]);
/// serialization always emits the current shape (`ccmode` + 124-byte
/// `reserved`). Components that only forward evidence should pass the raw
/// JSON through rather than deserializing and re-serializing it, otherwise
/// legacy evidence is upgraded and older verifiers can no longer read it.
#[repr(C)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(try_from = "BodyRepr")]
pub struct Body {
    /// Version number of the attestation report format (`< 2` is legacy)
    pub version: u32,
    /// Unique identifier of the hardware chip (16 bytes)
    pub chip_id: [u8; 16],
    /// User data value (64 bytes)
    #[serde(with = "serde_bytes")]
    pub user_data: [u8; 64],
    /// Measurement data (32 bytes)
    pub measure: [u8; 32],
    /// CC mode (4 bytes). Only meaningful when `version >= 2`; for legacy
    /// reports these are the first 4 bytes of the 128-byte reserved area.
    /// Prefer [`Body::cc_mode`] instead of reading this field directly.
    pub ccmode: u32,
    /// Reserved data (124 bytes). Legacy reports carry 128 bytes; use
    /// [`Body::reserved_bytes`] to get the version-appropriate slice.
    #[serde(with = "serde_bytes")]
    pub reserved: [u8; 124],
    /// Algorithm used for generating the signature
    pub sig_algo: u32,
    /// Indicates the purpose/usage of the signature
    pub sig_usage: u32,
}

impl TryFrom<BodyRepr> for Body {
    type Error = String;

    fn try_from(repr: BodyRepr) -> Result<Self, Self::Error> {
        match (repr.reserved.len(), repr.ccmode) {
            // Legacy producer: 128-byte reserved, no ccmode. Its field names
            // were opposite to the firmware offsets, so swap the signature
            // fields back to keep the raw 252 bytes (and the signature) intact.
            //
            // The shape is the only available producer marker. A third-party
            // producer that uses 128 bytes but already emits the firmware field
            // names would be swapped too and fail signature verification
            // (fail-closed, never accepted as valid).
            (128, None) => {
                let mut ccmode = [0u8; 4];
                ccmode.copy_from_slice(&repr.reserved[..4]);
                let mut reserved = [0u8; 124];
                reserved.copy_from_slice(&repr.reserved[4..]);

                Ok(Self {
                    version: repr.version,
                    chip_id: repr.chip_id,
                    user_data: repr.user_data,
                    measure: repr.measure,
                    ccmode: u32::from_le_bytes(ccmode),
                    reserved,
                    sig_algo: repr.sig_usage,
                    sig_usage: repr.sig_algo,
                })
            }
            // Current producer: ccmode + 124-byte reserved.
            (124, Some(ccmode)) => {
                let mut reserved = [0u8; 124];
                reserved.copy_from_slice(&repr.reserved);

                Ok(Self {
                    version: repr.version,
                    chip_id: repr.chip_id,
                    user_data: repr.user_data,
                    measure: repr.measure,
                    ccmode,
                    reserved,
                    sig_algo: repr.sig_algo,
                    sig_usage: repr.sig_usage,
                })
            }
            (128, Some(_)) => Err("ccmode present with 128-byte reserved".into()),
            (124, None) => Err("ccmode missing for 124-byte reserved".into()),
            (len, _) => Err(format!("reserved must be 124 or 128 bytes, got {len}")),
        }
    }
}

impl Default for Body {
    /// Creates a default Body with all fields zero-initialized
    fn default() -> Self {
        Self {
            version: Default::default(),
            chip_id: Default::default(),
            user_data: [0u8; 64],
            measure: Default::default(),
            ccmode: Default::default(),
            reserved: [0u8; 124],
            sig_algo: Default::default(),
            sig_usage: Default::default(),
        }
    }
}

impl Body {
    /// First report-body version that carries `ccmode` and a 124-byte reserved.
    ///
    /// Firmware is expected to bump `version` to 2 (or later) once `ccmode` is
    /// present. Versions below 2 are treated as legacy; later versions are
    /// treated as carrying `ccmode`.
    const VERSION_CCMODE: u32 = 2;

    fn has_ccmode(&self) -> bool {
        self.version >= Self::VERSION_CCMODE
    }

    /// Returns the report's CC mode, or `None` for legacy reports
    /// (`version < 2`) where the field is part of the reserved area.
    pub fn cc_mode(&self) -> Option<u32> {
        self.has_ccmode().then_some(self.ccmode)
    }

    /// Returns the reserved field as represented on the wire: 128 bytes for
    /// legacy reports (`version < 2`) and 124 bytes otherwise.
    pub fn reserved_bytes(&self) -> Vec<u8> {
        if self.has_ccmode() {
            self.reserved.to_vec()
        } else {
            let mut bytes = Vec::with_capacity(128);
            bytes.extend_from_slice(&self.ccmode.to_le_bytes());
            bytes.extend_from_slice(&self.reserved);
            bytes
        }
    }

    /// Prints each field of the `Body` struct in human-readable format
    pub fn print_fields(&self) {
        trace!("Version: {}", self.version);
        trace!("Chip ID: {}", String::from_utf8_lossy(&self.chip_id));
        trace!("User data: {}", encode(self.user_data));
        trace!("Measure: {:?}", self.measure);
        if let Some(ccmode) = self.cc_mode() {
            trace!("CC Mode: {}", ccmode);
        }
        trace!("Signature Algorithm: {}", self.sig_algo);
        trace!("Signature Usage: {}", self.sig_usage);
    }
}

/// This structure contains both the report body and its cryptographic signature.
#[repr(C)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttestationReport {
    /// The main content of the attestation report
    pub body: Body,
    /// ECDSA signature verifying the report authenticity
    pub sig: ecdsa::Signature,
}

impl AttestationReport {
    /// Prints both the body and signature fields of the attestation report
    pub fn print_report(&self) {
        self.body.print_fields();
        self.sig.print_fields();
    }
}

impl Default for AttestationReport {
    /// Creates a default AttestationReport with empty body and signature
    fn default() -> Self {
        Self {
            body: Default::default(),
            sig: Default::default(),
        }
    }
}

/// Response structure containing the attestation report from the dcu devices
#[repr(C)]
#[derive(Debug, serde::Deserialize)]
pub struct AttestationResponse {
    /// Size of the contained report in bytes
    pub report_size: u32,
    /// Reserved space for future extensions (28 bytes)
    pub reserved: [u8; 28],
    /// The actual attestation report data
    pub report: AttestationReport,
}

impl Default for AttestationResponse {
    /// Creates a default response with zero-sized report and empty fields
    fn default() -> Self {
        Self {
            report_size: 0,
            reserved: [0u8; 28],
            report: AttestationReport::default(),
        }
    }
}

impl AttestationResponse {
    /// Safely constructs a mutable reference from a raw C pointer
    /// # Safety
    /// Caller must ensure the pointer is valid and properly aligned
    pub unsafe fn from_raw<'a>(ptr: *mut c_void) -> Option<&'a mut Self> {
        if ptr.is_null() {
            None
        } else {
            Some(&mut *(ptr as *mut Self))
        }
    }
}

/// Implementation of encoding functionality for AttestationReport
impl codicon::Encoder<crate::Body> for AttestationReport {
    type Error = std::io::Error;

    /// Encodes the report body into the writer
    fn encode(&self, mut writer: impl Write, _: crate::Body) -> Result<(), std::io::Error> {
        writer.save(&self.body)
    }
}

impl TryFrom<&AttestationReport> for Signature {
    type Error = std::io::Error;

    /// Attempts to convert an AttestationReport into a Signature structure
    #[inline]
    fn try_from(value: &AttestationReport) -> Result<Self, std::io::Error> {
        let sig = Vec::try_from(&value.sig)?;
        Ok(Self {
            sig,
            id: None,
            usage: Usage::CEK,
            algo: None,
        })
    }
}

/// Implementation of verification for a certificate and attestation report pair
impl Verifiable for (&Certificate, &AttestationReport) {
    type Output = ();

    /// Verifies the attestation report using the provided certificate
    fn verify(self) -> Result<(), std::io::Error> {
        let key: PublicKey = self.0.try_into()?;
        let sig: Signature = self.1.try_into()?;
        key.verify(
            self.1,
            &self.0.body.data.user_id[..self.0.body.data.uid_size as usize],
            &sig,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Body;
    use crate::util::TypeSave;
    use serde_json::json;
    use std::mem::{offset_of, size_of};

    fn body_json(
        version: u32,
        reserved: Vec<u8>,
        ccmode: Option<u32>,
        sig_algo: u32,
        sig_usage: u32,
    ) -> serde_json::Value {
        let mut body = json!({
            "version": version,
            "chip_id": vec![0u8; 16],
            "user_data": vec![0u8; 64],
            "measure": vec![0u8; 32],
            "reserved": reserved,
            "sig_algo": sig_algo,
            "sig_usage": sig_usage,
        });
        if let Some(ccmode) = ccmode {
            body.as_object_mut()
                .unwrap()
                .insert("ccmode".to_string(), json!(ccmode));
        }
        body
    }

    #[test]
    fn body_layout_matches_firmware() {
        assert_eq!(size_of::<Body>(), 252);
        assert_eq!(offset_of!(Body, ccmode), 116);
        assert_eq!(offset_of!(Body, reserved), 120);
        assert_eq!(offset_of!(Body, sig_algo), 244);
        assert_eq!(offset_of!(Body, sig_usage), 248);
    }

    #[test]
    fn legacy_json_keeps_raw_body_bytes() {
        let reserved: Vec<u8> = (0..128).map(|i| i as u8).collect();
        let body: Body =
            serde_json::from_value(body_json(1, reserved.clone(), None, 0x55667788, 0x11223344))
                .unwrap();

        assert_eq!(body.version, 1);
        assert_eq!(body.cc_mode(), None);
        assert_eq!(body.reserved_bytes(), reserved);
        // Legacy JSON named the firmware offsets the other way round.
        assert_eq!(body.sig_algo, 0x11223344);
        assert_eq!(body.sig_usage, 0x55667788);

        let mut raw = Vec::new();
        raw.save(&body).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&[0u8; 16]);
        expected.extend_from_slice(&[0u8; 64]);
        expected.extend_from_slice(&[0u8; 32]);
        expected.extend_from_slice(&reserved);
        expected.extend_from_slice(&0x11223344u32.to_le_bytes());
        expected.extend_from_slice(&0x55667788u32.to_le_bytes());

        assert_eq!(raw, expected);
    }

    #[test]
    fn v2_json_uses_ccmode_and_124_byte_reserved() {
        let reserved: Vec<u8> = (0..124).map(|i| (i + 4) as u8).collect();
        let body: Body = serde_json::from_value(body_json(
            2,
            reserved.clone(),
            Some(1),
            0xaabbccdd,
            0xeeff0011,
        ))
        .unwrap();

        assert_eq!(body.cc_mode(), Some(1));
        assert_eq!(body.reserved_bytes(), reserved);
        assert_eq!(body.sig_algo, 0xaabbccdd);
        assert_eq!(body.sig_usage, 0xeeff0011);

        // Serialization is unchanged: it always emits ccmode + 124-byte reserved.
        let value = serde_json::to_value(&body).unwrap();
        assert_eq!(value["ccmode"], json!(1));
        assert_eq!(value["reserved"].as_array().unwrap().len(), 124);
    }

    #[test]
    fn version_selects_ccmode_semantics() {
        // Legacy shape with version 2: ccmode comes from the reserved prefix.
        let mut reserved = vec![0u8; 128];
        reserved[..4].copy_from_slice(&7u32.to_le_bytes());
        let legacy_v2: Body =
            serde_json::from_value(body_json(2, reserved.clone(), None, 1, 2)).unwrap();
        assert_eq!(legacy_v2.cc_mode(), Some(7));
        // version 2 semantics: the first 4 bytes are ccmode, not reserved.
        assert_eq!(legacy_v2.reserved_bytes(), reserved[4..].to_vec());

        // Current shape with version 1: ccmode is ignored, reserved is 128 bytes.
        let current_v1: Body =
            serde_json::from_value(body_json(1, vec![0x5a; 124], Some(1), 3, 4)).unwrap();
        assert_eq!(current_v1.cc_mode(), None);
        let mut expected = 1u32.to_le_bytes().to_vec();
        expected.extend_from_slice(&[0x5a; 124]);
        assert_eq!(current_v1.reserved_bytes(), expected);
    }

    #[test]
    fn rejects_ambiguous_or_truncated_reserved() {
        assert!(serde_json::from_value::<Body>(body_json(2, vec![0u8; 124], None, 1, 2)).is_err());
        assert!(
            serde_json::from_value::<Body>(body_json(2, vec![0u8; 128], Some(1), 1, 2)).is_err()
        );
        assert!(serde_json::from_value::<Body>(body_json(2, vec![0u8; 127], None, 1, 2)).is_err());
    }

    #[test]
    fn default_version_is_legacy() {
        let body = Body::default();
        assert_eq!(body.cc_mode(), None);
        assert_eq!(body.reserved_bytes().len(), 128);
    }
}
