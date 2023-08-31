// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use codicon::Decoder;
use csv_rs::certs::{builtin::HRK, ca, Verifiable};

#[test]
fn verify() {
    let hrk = ca::Certificate::decode(&mut &HRK[..], ()).unwrap();
    let hsk = ca::Certificate::decode(&mut &HSK[..], ()).unwrap();
    (&hrk, &hsk).verify().unwrap();
}
