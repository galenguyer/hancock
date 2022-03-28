use clap::Parser;

use hancock::path;
use hancock::pkey;
use hancock::root;
use hancock::KeyType;

use std::path::Path;

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
                root::save_root_cert(&cert_path, &cert);
            }
        }
    }
}
