use clap::Parser;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private, self};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::*;

use hancock::KeyType;
use hancock::path;

use std::path::Path;
use std::fs::{read, write};

mod cli;
use crate::cli::*;

fn main() {
    let cli = dbg!(Cli::parse());

    match cli.command {
        Commands::Init(args) => {
            let base_dir = path::base_dir(&args.base_dir);

            let key_type = match args.key_type.to_uppercase().as_str() {
                "RSA" => KeyType::Rsa(args.key_length),
                "ECDSA" => KeyType::Ecdsa,
                _ => panic!("key_type not ECDSA or RSA after validation. This should never happen"),
            };

            let pkey_path = path::ca_pkey(&base_dir, key_type);

            let pkey = match Path::new(&pkey_path).exists() {
                true => {
                    PKey::private_key_from_pem(&read(&pkey_path).unwrap()).unwrap()
                }, 
                false => {
                    let pkey = generate_pkey(key_type);
                    save_pkey(&pkey_path, &pkey);
                    pkey
                }
            };
        }
    }

    // let key_type = KeyType::Ecdsa;
    // let pkey = generate_pkey(key_type);
    // let root_cert = generate_root_cert(pkey);
}

fn generate_pkey(key_type: KeyType) -> PKey<Private> {
    match key_type {
        KeyType::Ecdsa => PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap()).unwrap(),
        )
        .unwrap(),
        KeyType::Rsa(bits) => PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap(),
    }
}

fn save_pkey(path: &str, key: &PKey<Private>) {
    println!("{}", path);
    path::ensure_dir(path);
    write(path, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
}

fn generate_root_cert(pkey: PKey<Private>) -> X509 {
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

    x509_builder.build()
}
