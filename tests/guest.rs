// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use codicon::Decoder;
use csv_rs::{
    api::guest::*,
    certs::{builtin::HRK, ca, csv, Verifiable},
};

use hyper::body::HttpBody as _;
use hyper::Client;
use hyper_tls::HttpsConnector;
use tokio::runtime::Runtime;

fn xor_anonce(data: &mut [u8], anonce_u32: u32) {
    let mut anonce = [0u8; 4];
    anonce[..].copy_from_slice(&anonce_u32.to_le_bytes());
    for (index, item) in data.iter_mut().enumerate() {
        *item ^= anonce[index % 4];
    }
}

#[cfg_attr(not(has_dev_csv_guest), ignore)]
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

    let mut csv_guest = CsvGuest::open().unwrap();

    let report = csv_guest.get_report(Some(data), Some(mnonce)).unwrap();

    let report = AttestationReport::try_from(&report).unwrap();

    xor_anonce(&mut data, report.tee_info().anonce());
    xor_anonce(&mut mnonce, report.tee_info().anonce());

    assert_eq!(mnonce, *report.tee_info().mnonce());
    assert_eq!(data, *report.tee_info().report_data());
    assert_eq!([0u8; 32], report.signer().reserved);
}

#[cfg_attr(not(has_dev_csv_guest), ignore)]
#[test]
fn get_report_without_input() {
    let mut data: [u8; 64] = [0; 64];

    let mut csv_guest = CsvGuest::open().unwrap();

    let report = csv_guest.get_report(None, None).unwrap();
    let report = AttestationReport::try_from(&report).unwrap();

    xor_anonce(&mut data, report.tee_info().anonce());

    assert_eq!(data, *report.tee_info().report_data());
    assert_eq!([0u8; 32], report.signer().reserved);
}

fn download_hskcek(sn: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let mut kds_url = String::from("https://cert.hygon.cn/hsk_cek?snumber=");
    let chip_id = std::str::from_utf8(sn)?.trim_end_matches('\0');

    kds_url += chip_id;

    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);

    let request = hyper::Request::builder()
        .uri(kds_url)
        .method(hyper::Method::GET)
        .header("User-Agent", "Hyper")
        .body(hyper::Body::empty())?;

    let rt = Runtime::new()?;
    let response = rt.block_on(client.request(request))?;

    let mut response_body = Vec::new();
    let mut response = response.into_body();
    while let Some(chunk) = rt.block_on(response.data()) {
        let chunk = chunk?;
        response_body.extend_from_slice(&chunk);
    }

    Ok(response_body)
}

#[cfg_attr(not(has_dev_csv_guest), ignore)]
#[test]
fn get_report_and_verify() {
    let mut data: [u8; 64] = [
        103, 198, 105, 115, 81, 255, 74, 236, 41, 205, 186, 171, 242, 251, 227, 70, 124, 194, 84,
        248, 27, 232, 231, 141, 118, 90, 46, 99, 51, 159, 201, 154, 102, 50, 13, 183, 49, 88, 163,
        90, 37, 93, 5, 23, 88, 233, 94, 212, 171, 178, 205, 198, 155, 180, 84, 17, 14, 130, 116,
        65, 33, 61, 220, 135,
    ];

    let mut csv_guest = CsvGuest::open().unwrap();

    let report = csv_guest.get_report(Some(data), None).unwrap();
    let report = AttestationReport::try_from(&report).unwrap();

    if let Ok(cert_data) = download_hskcek(&report.signer().sn) {
        let mut cert_data = &cert_data[..];
        let hsk = ca::Certificate::decode(&mut cert_data, ()).unwrap();
        let cek = csv::Certificate::decode(&mut cert_data, ()).unwrap();
        let pek = csv::Certificate::decode(&mut &report.signer().pek_cert[..], ()).unwrap();
        let hrk = ca::Certificate::decode(&mut &HRK[..], ()).unwrap();

        (&hrk, &hrk).verify().unwrap();
        (&hrk, &hsk).verify().unwrap();
        (&hsk, &cek).verify().unwrap();
        (&cek, &pek).verify().unwrap();
        (&pek, &report.tee_info()).verify().unwrap();

        xor_anonce(&mut data, report.tee_info().anonce());

        assert_eq!(data, *report.tee_info().report_data());
        assert_eq!([0u8; 32], report.signer().reserved);
    } else {
        assert!(false);
    }
}
