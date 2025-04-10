// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use codicon::Decoder;
use csv_rs::{
    api::dcu::*,
    certs::{builtin::HRK, ca, csv, Verifiable},
};

use hyper::body::HttpBody as _;
use hyper::Client;
use hyper_tls::HttpsConnector;
use tokio::runtime::Runtime;

#[test]
fn get_report() {
    let mut data: [u8; 64] = [
        103, 198, 105, 115, 81, 255, 74, 236, 41, 205, 186, 171, 242, 251, 227, 70, 124, 194, 84,
        248, 27, 232, 231, 141, 118, 90, 46, 99, 51, 159, 201, 154, 102, 50, 13, 183, 49, 88, 163,
        90, 37, 93, 5, 23, 88, 233, 94, 212, 171, 178, 205, 198, 155, 180, 84, 17, 14, 130, 116,
        65, 33, 61, 220, 135,
    ];
    let mut mnonce: [u8; 16] = [
        112, 233, 62, 161, 65, 225, 252, 103, 62, 1, 126, 151, 234, 220, 107, 150,
    ];

    let mut dcu_guest: DcuGuest = DcuGuest::open().unwrap();

    let (report) = dcu_guest.get_report(Some(data), Some(mnonce)).unwrap();



    assert_eq!(mnonce, report.body.mnonce);

}
