use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Private};
use openssl::x509::extension::*;
use openssl::x509::*;

use crate::path;
use std::fs::{read, write, File};
use std::os::unix::prelude::PermissionsExt;

pub fn generate_cert(
    lifetime_days: u32,
    signing_request: &X509Req,
    intermediate: bool,
    ca_cert: &X509,
    ca_key_pair: &PKey<Private>,
) -> X509 {
    let mut x509_builder = X509::builder().unwrap();
    x509_builder.set_version(2).unwrap();

    x509_builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    x509_builder
        .set_not_after(&Asn1Time::days_from_now(lifetime_days).unwrap())
        .unwrap();

    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    x509_builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();

    x509_builder
        .set_issuer_name(ca_cert.subject_name())
        .unwrap();
    x509_builder
        .set_subject_name(signing_request.subject_name())
        .unwrap();

    x509_builder
        .set_pubkey(&signing_request.public_key().unwrap())
        .unwrap();

    let basic_constraints = match intermediate {
        false => BasicConstraints::new().critical().build().unwrap(),
        true => BasicConstraints::new().critical().ca().build().unwrap(),
    };
    x509_builder.append_extension(basic_constraints).unwrap();

    let key_usage = match intermediate {
        true => KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap(),
        false => KeyUsage::new()
            .critical()
            .digital_signature()
            .key_encipherment()
            .build()
            .unwrap(),
    };
    x509_builder.append_extension(key_usage).unwrap();

    if !intermediate {
        let extended_key_usage = ExtendedKeyUsage::new()
            .client_auth()
            .server_auth()
            .build()
            .unwrap();
        x509_builder.append_extension(extended_key_usage).unwrap();

        // TODO: It'd be cool if this ignored anything but SANs
        // but I'm not sure if that's possible
        if !signing_request.extensions().unwrap().is_empty() {
            for extension in signing_request.extensions().unwrap() {
                x509_builder.append_extension(extension).unwrap();
            }
        }
    }

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&x509_builder.x509v3_context(Some(ca_cert), None))
        .unwrap();
    x509_builder
        .append_extension(subject_key_identifier)
        .unwrap();

    let authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&x509_builder.x509v3_context(Some(ca_cert), None))
        .unwrap();
    x509_builder
        .append_extension(authority_key_identifier)
        .unwrap();

    let digest_algorithm = match signing_request.public_key().unwrap().id() {
        Id::RSA => MessageDigest::sha256(),
        Id::EC => MessageDigest::sha384(),
        _ => MessageDigest::sha256(),
    };

    x509_builder.sign(ca_key_pair, digest_algorithm).unwrap();

    x509_builder.build()
}

pub fn save_cert(path: &str, cert: &X509) {
    path::ensure_dir(path);
    let file = File::create(path).unwrap();
    let mut permissions = file.metadata().unwrap().permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions).unwrap();
    write(path, cert.to_pem().unwrap()).unwrap();
}

pub fn read_cert(path: &str) -> X509 {
    X509::from_pem(&read(path).unwrap()).unwrap()
}
