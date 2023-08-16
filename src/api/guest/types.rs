// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::error::*;
use crate::{
    certs::{Verifiable, Usage, csv::Certificate},
    crypto::{PublicKey, sig::ecdsa, Signature},
    util::*,
};

use openssl::{
    hash::{Hasher, MessageDigest},
    pkey,
    sign,
};

use static_assertions::const_assert;

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::io::Write;

use bitfield::bitfield;

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

#[repr(C)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Body {
    pub user_pubkey_digest: [u8; 32],
    pub vm_id: [u8; 16],
    pub vm_version: [u8; 16],
    #[serde(with = "BigArray")]
    pub report_data: [u8; 64],
    pub mnonce: [u8; 16],
    pub measure: [u8; 32],
    pub policy: GuestPolicy,
}

impl Default for Body {
    fn default() -> Self {
        Self {
            user_pubkey_digest: Default::default(),
            vm_id: Default::default(),
            vm_version: Default::default(),
            report_data: [0u8; 64],
            mnonce: Default::default(),
            measure: Default::default(),
            policy: Default::default(),
        }
    }
}

/// Data provieded by the guest owner for requesting an attestation report
/// from the HYGON Secure Processor.
#[repr(C)]
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationReport {
    pub body: Body,
    pub sig_usage: u32,
    pub sig_algo: u32,
    pub anonce: u32,
    pub sig: ecdsa::Signature,
}

impl Default for AttestationReport {
    fn default() -> Self {
        Self {
            body: Default::default(),
            sig_usage: Default::default(),
            sig_algo: Default::default(),
            anonce: Default::default(),
            sig: Default::default(),
        }
    }
}

impl codicon::Encoder<crate::Body> for AttestationReport {
    type Error = std::io::Error;

    fn encode(&self, mut writer: impl Write, _: crate::Body) -> Result<(), std::io::Error> {
        writer.save(&self.body)
    }
}

impl TryFrom<&AttestationReport> for Signature {
    type Error = std::io::Error;

    #[inline]
    fn try_from(value: &AttestationReport) -> Result<Self, std::io::Error> {
        let sig = Vec::try_from(&value.sig)?;
        Ok(Self {
            sig,
            id: None,
            usage: Usage::PEK.into(),
            algo: None,
        })
    }
}

impl Verifiable for (&Certificate, &AttestationReport) {
    type Output = ();

    fn verify(self) -> Result<(), std::io::Error> {
        let key: PublicKey = self.0.try_into()?;
        let sig: Signature = self.1.try_into()?;
        key.verify(self.1, &self.0.body.data.user_id[..self.0.body.data.uid_size as usize], &sig)
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
    #[derive(Copy, Clone, Serialize, Deserialize, Default)]
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
#[derive(Serialize, Deserialize)]
pub struct ReportSigner {
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

impl ReportSigner {
    /// Verifies the signature evidence's hmac.
    pub fn verify(&mut self, input_mnonce: &[u8], mnonce: &[u8], anonce: &u32) -> Result<(), Error> {
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