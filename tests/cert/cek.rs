// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use csv_rs::certs::{ca, csv, Verifiable};
use codicon::Decoder;

#[test]
fn verify() {
    let hsk = ca::Certificate::decode(&mut &HSK[..], ()).unwrap();
    let cek = csv::Certificate::decode(&mut &CEK[..], ()).unwrap();
    (&hsk, &cek).verify().unwrap();
}
