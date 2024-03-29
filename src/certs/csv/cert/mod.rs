// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Operations that can be done on a CSV certificate.

pub mod key;

use crate::{
    certs::{ca, Algorithm, Signer, Usage, Verifiable},
    crypto::{self, key::ecc, sig::ecdsa, sm, PrivateKey, PublicKey, Signature},
    util::*,
};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::io::{Error, ErrorKind, Read, Result, Write};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Deserialize, Serialize)]
pub struct Data {
    pub firmware: crate::Version,
    pub reserved1: u16,
    pub pubkey: key::PubKey,
    pub uid_size: u16,
    #[serde(with = "BigArray")]
    pub user_id: [u8; 254],
    pub sid: [u8; 16],
    #[serde(with = "BigArray")]
    pub reserved2: [u8; 608],
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Deserialize, Serialize)]
pub struct Body {
    pub ver: u32,
    pub data: Data,
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Deserialize, Serialize)]
pub struct Signatures {
    usage: Usage,
    algo: Algorithm,
    signature: ecdsa::Signature,
    #[serde(with = "BigArray")]
    _reserved: [u8; 368],
}

impl Default for Signatures {
    fn default() -> Self {
        let _reserved = [0u8; 368];
        Signatures {
            usage: Usage::INV,
            algo: Algorithm::NONE,
            signature: ecdsa::Signature::default(),
            _reserved,
        }
    }
}

impl TryFrom<&crypto::Signature> for Signatures {
    type Error = Error;

    #[inline]
    fn try_from(value: &crypto::Signature) -> Result<Self> {
        let algo = value.algo.unwrap_or_else(|| Algorithm::NONE);
        Ok(Signatures {
            usage: value.usage,
            algo,
            signature: ecdsa::Signature::try_from(&value.sig[..])?,
            _reserved: [0u8; 368],
        })
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Deserialize, Serialize)]
pub struct Certificate {
    pub body: Body,
    pub sigs: [Signatures; 2],
}

impl TryFrom<&Signatures> for Option<Signature> {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signatures) -> Result<Self> {
        if value.is_empty() {
            return Ok(None);
        }

        let usage = value.usage;
        let algo = value.algo;
        let sig = Vec::try_from(&value.signature)?;
        Ok(Some(Signature {
            sig,
            usage,
            algo: Some(algo),
            id: None,
        }))
    }
}

impl TryFrom<&Certificate> for [Option<Signature>; 2] {
    type Error = Error;

    #[inline]
    fn try_from(value: &Certificate) -> Result<Self> {
        Ok([(&value.sigs[0]).try_into()?, (&value.sigs[1]).try_into()?])
    }
}

impl TryFrom<&Certificate> for PublicKey {
    type Error = Error;

    fn try_from(value: &Certificate) -> Result<Self> {
        let key = value.body.data.pubkey.key;
        Ok(Self {
            id: None,
            key,
            usage: value.body.data.pubkey.usage,
            algo: Some(value.body.data.pubkey.algo),
        })
    }
}

impl Signer<Certificate> for PrivateKey<Usage> {
    type Output = ();

    fn sign(&self, target: &mut Certificate, uid: String) -> Result<()> {
        let slot = if target.sigs[0].is_empty() {
            &mut target.sigs[0]
        } else if target.sigs[1].is_empty() {
            &mut target.sigs[1]
        } else {
            return Err(ErrorKind::InvalidInput.into());
        };

        let mut msg: Vec<u8> = Vec::new();
        msg.save(&target.body)?;

        let sig = sm::SM2::sign(self.key, &uid.as_bytes().to_vec(), &msg)?;

        let sig = crate::crypto::Signature {
            usage: self.usage.into(),
            sig,
            algo: Some(self.usage.try_into()?),
            id: self.id,
        };

        *slot = Signatures::try_from(&sig)?;

        Ok(())
    }
}

impl Verifiable for (&Certificate, &Certificate) {
    type Output = ();

    fn verify(self) -> Result<()> {
        let key: PublicKey = self.0.try_into()?;

        let sigs: [Option<Signature>; 2] = self.1.try_into()?;
        for sig in sigs.iter().flatten() {
            if key
                .verify(
                    self.1,
                    &self.0.body.data.user_id[..self.0.body.data.uid_size as usize],
                    sig,
                )
                .is_ok()
            {
                return Ok(());
            }
        }

        Err(ErrorKind::InvalidInput.into())
    }
}

impl Verifiable for (&ca::cert::Certificate, &Certificate) {
    type Output = ();

    fn verify(self) -> Result<()> {
        let key: PublicKey = self.0.try_into()?;
        let sigs: [Option<Signature>; 2] = self.1.try_into()?;
        for sig in sigs.iter().flatten() {
            if key
                .verify(
                    self.1,
                    &self.0.body.user_id[..self.0.body.uid_size as usize],
                    sig,
                )
                .is_ok()
            {
                return Ok(());
            }
        }
        Err(ErrorKind::InvalidInput.into())
    }
}

impl codicon::Decoder<()> for Signatures {
    type Error = Error;

    #[inline]
    fn decode(mut reader: impl Read, _: ()) -> Result<Self> {
        let mut _reserved = [0u8; 368];
        let usage: Usage = reader.load()?;
        let algo: Algorithm = reader.load()?;
        let signature: ecdsa::Signature = reader.load()?;
        reader.read_exact(&mut _reserved)?;
        Ok(Self {
            usage,
            algo,
            signature,
            _reserved,
        })
    }
}

impl codicon::Decoder<()> for Certificate {
    type Error = Error;

    fn decode(mut reader: impl Read, _: ()) -> Result<Self> {
        let body: Body = reader.load()?;
        let sig1 = Signatures::decode(&mut reader, ())?;
        let sig2 = Signatures::decode(&mut reader, ())?;
        Ok(Self {
            body,
            sigs: [sig1, sig2],
        })
    }
}

impl codicon::Encoder<crate::Body> for Certificate {
    type Error = Error;

    fn encode(&self, mut writer: impl Write, _: crate::Body) -> Result<()> {
        writer.save(&self.body)
    }
}

impl TryFrom<&Certificate> for Usage {
    type Error = Error;

    fn try_from(value: &Certificate) -> Result<Self> {
        Ok(value.body.data.pubkey.usage)
    }
}

impl Signatures {
    pub fn is_empty(&self) -> bool {
        match self.usage {
            Usage::CEK | Usage::HRK | Usage::HSK | Usage::OCA | Usage::PDH | Usage::PEK => {
                !matches!(self.algo, Algorithm::SM2_SA | Algorithm::SM2_DH)
            }
            _ => true,
        }
    }
}

impl Body {
    pub fn generate(usage: Usage, uid: Option<String>) -> Result<(Body, PrivateKey<Usage>)> {
        let uid: String = if let Some(value) = uid {
            value
        } else {
            String::try_from(usage)?
        };

        let uid_size = if let Some(u16_value) = uid.len().try_into().ok() {
            u16_value
        } else {
            return Err(ErrorKind::InvalidInput.into());
        };
        let mut user_id_vec = Vec::from(uid.as_bytes());
        user_id_vec.resize(254, 0);
        let mut user_id: [u8; 254] = [0; 254];
        user_id.copy_from_slice(&user_id_vec);
        let (pubkey, prv) = key::PubKey::generate(usage, None)?;
        Ok((
            Body {
                ver: 1u32.to_le(),
                data: Data {
                    firmware: Default::default(),
                    reserved1: 0,
                    pubkey,
                    uid_size,
                    user_id,
                    sid: [0u8; 16],
                    reserved2: [0u8; 608],
                },
            },
            prv,
        ))
    }
}

impl Certificate {
    /// Generates a private key and its public certificate.
    pub fn generate(usage: Usage, uid: Option<String>) -> Result<(Self, PrivateKey<Usage>)> {
        let (body, prv) = Body::generate(usage, uid)?;
        Ok((
            Self {
                body,
                sigs: [Signatures::default(), Signatures::default()],
            },
            prv,
        ))
    }

    /// Encrypts a buffer with the certificate's SM2 public key.
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let key: PublicKey = self.try_into()?;
        key.encrypt(data)
    }
}
