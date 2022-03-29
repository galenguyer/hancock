use clap::Parser;

use hancock::*;

use std::path::Path;

mod cli;
use crate::cli::*;

fn main() {
    let cli = dbg!(Cli::parse());

    match cli.command {
        Commands::Init(args) => init(args),
        Commands::Issue(args) => issue(args),
    }
}

fn init(args: Init) {
    let base_dir = path::base_dir(&args.base_dir);

    let key_type = match args.key_type.to_uppercase().as_str() {
        "RSA" => KeyType::Rsa(args.key_length),
        "ECDSA" => KeyType::Ecdsa,
        _ => panic!("key_type not ECDSA or RSA after validation. This should never happen"),
    };

    let pkey_path = path::ca_pkey(&base_dir, key_type);

    let pkey = match Path::new(&pkey_path).exists() {
        true => pkey::read_pkey(&pkey_path, args.password),
        false => {
            let pkey = pkey::generate_pkey(key_type);
            pkey::save_pkey(&pkey_path, &pkey, args.password);
            pkey
        }
    };

    let cert_path = path::ca_crt(&base_dir, key_type);
    if !Path::new(&cert_path).exists() {
        let cert = root::generate_root_cert(
            args.lifetime,
            &args.common_name,
            &args.country,
            &args.state,
            &args.locality,
            &args.organization,
            &args.organizational_unit,
            &pkey,
        );
        cert::save_cert(&cert_path, &cert);
    }
}

fn issue(args: Issue) {
    let base_dir = path::base_dir(&args.base_dir);

    let key_type = match args.key_type.to_uppercase().as_str() {
        "RSA" => KeyType::Rsa(args.key_length),
        "ECDSA" => KeyType::Ecdsa,
        _ => panic!("key_type not ECDSA or RSA after validation. This should never happen"),
    };

    let ca_pkey_path = path::ca_pkey(&base_dir, key_type);

    let ca_pkey = match Path::new(&ca_pkey_path).exists() {
        true => pkey::read_pkey(&ca_pkey_path, args.password),
        false => {
            let pkey = pkey::generate_pkey(key_type);
            pkey::save_pkey(&ca_pkey_path, &pkey, args.password);
            pkey
        }
    };

    let ca_cert_path = path::ca_crt(&base_dir, key_type);
    let ca_cert = cert::read_cert(&ca_cert_path);

    let pkey_path = path::cert_pkey(&base_dir, &args.common_name, key_type);
    let pkey = match Path::new(&pkey_path).exists() {
        true => pkey::read_pkey(&pkey_path, None),
        false => {
            let pkey = pkey::generate_pkey(key_type);
            pkey::save_pkey(&pkey_path, &pkey, None);
            pkey
        }
    };

    let x509_req_path = path::cert_csr(&base_dir, &args.common_name, key_type);
    let x509_req = {
        let req = req::generate_req(
            &Some(args.common_name.clone()),
            &args.country,
            &args.state,
            &args.locality,
            &args.organization,
            &args.organizational_unit,
            &args.subject_alt_names,
            &pkey,
        );
        req::save_req(&x509_req_path, &req);
        req
    };

    let cert = cert::generate_cert(args.lifetime, &x509_req, &ca_cert, &ca_pkey);
    cert::save_cert(
        &path::cert_crt(&base_dir, &args.common_name, key_type),
        &cert,
    );
}
