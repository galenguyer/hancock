#![feature(test)]

extern crate test;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::*;

fn main() {
    rsa(2048_u32);
    ecdsa();
}

fn ecdsa() {
    let ec = EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap()).unwrap();
    // println!("{}", String::from_utf8(ec.private_key_to_pem().unwrap()).unwrap());
    let pkey = PKey::from_ec_key(ec).unwrap();

    let mut x509_name = X509Name::builder().unwrap();
    x509_name
        .append_entry_by_nid(Nid::COMMONNAME, "ligma.dev")
        .unwrap();
    let x509_name = x509_name.build();

    let mut x509_builder = X509::builder().unwrap();
    x509_builder.set_version(2).unwrap();
    x509_builder.set_issuer_name(&x509_name).unwrap();
    x509_builder.set_subject_name(&x509_name).unwrap();

    x509_builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    x509_builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();

    x509_builder.set_pubkey(&pkey).unwrap();

    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    x509_builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();

    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    x509_builder.append_extension(basic_constraints).unwrap();
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    x509_builder.append_extension(key_usage).unwrap();

    x509_builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let x509 = x509_builder.build();

    println!("{}", String::from_utf8(x509.to_pem().unwrap()).unwrap());
}

pub fn rsa(key_size: u32) {
    let rsa = Rsa::generate(key_size).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    // println!("{}", String::from_utf8(rsa.private_key_to_pem().unwrap()).unwrap());

    let mut x509_name = X509Name::builder().unwrap();
    x509_name
        .append_entry_by_nid(Nid::COMMONNAME, "ligma.dev")
        .unwrap();
    let x509_name = x509_name.build();

    let mut x509_builder = X509::builder().unwrap();
    x509_builder.set_version(2).unwrap();
    x509_builder.set_issuer_name(&x509_name).unwrap();
    x509_builder.set_subject_name(&x509_name).unwrap();

    x509_builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    x509_builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();

    x509_builder.set_pubkey(&pkey).unwrap();

    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    x509_builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();

    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    x509_builder.append_extension(basic_constraints).unwrap();
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    x509_builder.append_extension(key_usage).unwrap();

    x509_builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let x509 = x509_builder.build();

    println!("{}", String::from_utf8(x509.to_pem().unwrap()).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;

    #[bench]
    fn bench_rsa_2048(b: &mut Bencher) {
        b.iter(|| rsa(2048_u32));
    }

    #[bench]
    fn bench_rsa_4096(b: &mut Bencher) {
        b.iter(|| rsa(4096_u32));
    }

    #[bench]
    fn bench_ecdsa(b: &mut Bencher) {
        b.iter(|| ecdsa());
    }
}
