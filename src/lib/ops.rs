use clap::Args;
use std::path::Path;

use crate::KeyType;
use crate::*;

#[derive(Args, Debug)]
#[clap(about = "Generate a new root certificate")]
pub struct Init {
    /// Base directory to store certificates
    #[clap(long, default_value = "~/.hancock", env = "CA_BASE_DIR")]
    pub base_dir: String,

    /// Algorithm to generate private keys ('RSA' or 'ECDSA')
    #[clap(long, short = 't', default_value = "RSA", validator = validate_key_type)]
    pub key_type: String,

    /// Length to use when generating an RSA key. Ignored for ECDSA
    #[clap(long, short = 'b', default_value_t = 4096)]
    pub key_length: u32,

    /// Lifetime in days of the generated certificate
    #[clap(long, short = 'd', default_value_t = 365 * 10)]
    pub lifetime: u32,

    /// Certificate CommonName
    #[clap(long, short = 'n')]
    pub common_name: Option<String>,

    /// Certificate Country
    #[clap(long, short = 'c')]
    pub country: Option<String>,

    /// Certificate State or Province
    #[clap(long, short = 's')]
    pub state: Option<String>,

    /// Certificate Locality
    #[clap(long, short = 'l')]
    pub locality: Option<String>,

    /// Certificate Organization
    #[clap(long, short = 'o')]
    pub organization: Option<String>,

    /// Certificate Organizational Unit
    #[clap(long, short = 'u')]
    pub organizational_unit: Option<String>,

    /// Password for private key
    #[clap(long, short = 'p', env = "CA_PASSWORD")]
    pub password: Option<String>,
}

#[derive(Args, Debug)]
#[clap(about = "Issue a new certificate")]
pub struct Issue {
    /// Base directory to store certificates
    #[clap(long, default_value = "~/.hancock", env = "CA_BASE_DIR")]
    pub base_dir: String,

    /// Algorithm to generate private keys ('RSA' or 'ECDSA')
    #[clap(long, short = 't', default_value = "RSA", validator = validate_key_type)]
    pub key_type: String,

    /// Length to use when generating an RSA key. Ignored for ECDSA
    #[clap(long, short = 'b', default_value_t = 2048)]
    pub key_length: u32,

    /// Lifetime in days of the generated certificate
    #[clap(long, short = 'd', default_value_t = 90)]
    pub lifetime: u32,

    /// Certificate CommonName
    #[clap(long, short = 'n')]
    pub common_name: String,

    /// Certificate Country
    #[clap(long, short = 'c')]
    pub country: Option<String>,

    /// Certificate State or Province
    #[clap(long, short = 's')]
    pub state: Option<String>,

    /// Certificate Locality
    #[clap(long, short = 'l')]
    pub locality: Option<String>,

    /// Certificate Organization
    #[clap(long, short = 'o')]
    pub organization: Option<String>,

    /// Certificate Organizational Unit
    #[clap(long, short = 'u')]
    pub organizational_unit: Option<String>,

    /// Subject Alternative Names
    #[clap(long)]
    pub subject_alt_names: Option<String>,

    /// Password for private key
    #[clap(long, short = 'p', env = "CA_PASSWORD")]
    pub password: Option<String>,
}

pub fn init(args: Init) {
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

pub fn issue(args: Issue) {
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

fn validate_key_type(input: &str) -> Result<(), String> {
    let input = input.to_string().to_uppercase();
    if input == "RSA" || input == "ECDSA" {
        Ok(())
    } else {
        Err(format!(
            "{} is not a valid key type ['rsa', 'ecdsa']",
            input
        ))
    }
}
