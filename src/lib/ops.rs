use clap::Args;
use openssl::asn1::Asn1Time;
use openssl::nid::Nid;
use std::cmp::Ordering;
use std::fs;
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

#[derive(Args, Debug)]
#[clap(about = "List all known certificates")]
pub struct List {
    #[clap(long, default_value = "~/.hancock", env = "CA_BASE_DIR")]
    pub base_dir: String,
}

#[derive(Args, Debug)]
#[clap(about = "Renew a certificate or all if no Common Name is specified")]
pub struct Renew {
    /// Base directory to store certificates
    #[clap(long, default_value = "~/.hancock", env = "CA_BASE_DIR")]
    pub base_dir: String,

    /// Certificate CommonName
    #[clap(long, short = 'n')]
    pub common_name: Option<String>,

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

pub fn list(args: List) {
    let base_dir = path::base_dir(&args.base_dir);

    let rsa_ca_crt_path = path::ca_crt(&base_dir, KeyType::Rsa(0));
    if Path::new(&rsa_ca_crt_path).is_file() {
        let crt = cert::read_cert(&rsa_ca_crt_path);
        println!("{}", cert_info(crt));
    }

    let ecda_ca_crt_path = path::ca_crt(&base_dir, KeyType::Ecdsa);
    if Path::new(&ecda_ca_crt_path).is_file() {
        let crt = cert::read_cert(&ecda_ca_crt_path);
        println!("{}", cert_info(crt));
    }

    for name in fs::read_dir(&base_dir).unwrap() {
        let name = name.unwrap();
        if name.file_type().unwrap().is_dir() {
            let name = format!("{}", name.file_name().to_string_lossy());
            for key_type in [KeyType::Rsa(0), KeyType::Ecdsa] {
                let crt_path = path::cert_crt(&base_dir, &name, key_type);
                if Path::new(&crt_path).is_file() {
                    let crt = cert::read_cert(&crt_path);
                    println!("{}", cert_info(crt));
                }
            }
        }
    }
}

pub fn renew(args: Renew) {
    let base_dir = path::base_dir(&args.base_dir);

    let rsa_ca_crt_path = path::ca_crt(&base_dir, KeyType::Rsa(0));
    if Path::new(&rsa_ca_crt_path).is_file() {
        let crt = cert::read_cert(&rsa_ca_crt_path);
        println!("{}", cert_info(crt));
    }

    let ecda_ca_crt_path = path::ca_crt(&base_dir, KeyType::Ecdsa);
    if Path::new(&ecda_ca_crt_path).is_file() {
        let crt = cert::read_cert(&ecda_ca_crt_path);
        println!("{}", cert_info(crt));
    }

    for name in fs::read_dir(&base_dir).unwrap() {
        let name = name.unwrap();
        if name.file_type().unwrap().is_dir() {
            let name = format!("{}", name.file_name().to_string_lossy());
            for key_type in [KeyType::Rsa(0), KeyType::Ecdsa] {
                let crt_path = path::cert_crt(&base_dir, &name, key_type);
                if Path::new(&crt_path).is_file() {
                    let crt = cert::read_cert(&crt_path);
                    let now = Asn1Time::days_from_now(0).unwrap();
                    let original_lifetime = crt.not_before().diff(crt.not_after()).unwrap().days;

                    if now.diff(crt.not_after()).unwrap().days < 30 {
                        // TODO: handle expirations in the past
                        println!(
                            "{} expires in {} days, renewing for {} days",
                            get_cn(&crt).unwrap_or_else(|| String::from("Unknown CN")),
                            now.diff(crt.not_after()).unwrap().days,
                            original_lifetime
                        );

                        let ca_pkey_path = path::ca_pkey(&base_dir, key_type);

                        let ca_pkey = match Path::new(&ca_pkey_path).exists() {
                            true => pkey::read_pkey(&ca_pkey_path, args.password.clone()),
                            false => {
                                panic!("No private key for type {} found", key_type.to_string());
                            }
                        };

                        let ca_cert_path = path::ca_crt(&base_dir, key_type);
                        let ca_cert = cert::read_cert(&ca_cert_path);

                        let x509_req = req::read_req(&path::cert_csr(
                            &base_dir,
                            &get_cn(&crt).unwrap(),
                            key_type,
                        ));
                        let cert = cert::generate_cert(
                            original_lifetime as u32,
                            &x509_req,
                            &ca_cert,
                            &ca_pkey,
                        );
                        cert::save_cert(
                            &path::cert_crt(&base_dir, &get_cn(&crt).unwrap(), key_type),
                            &cert,
                        );
                    }
                }
            }
        }
    }
}

fn cert_info(crt: openssl::x509::X509) -> String {
    let now = Asn1Time::days_from_now(0).unwrap();

    let cn = get_cn(&crt).unwrap_or_else(|| String::from("Unknown CN"));
    let orig = crt.not_before().diff(crt.not_after()).unwrap().days;
    let ex = match now.compare(crt.not_after()).unwrap() {
        Ordering::Greater => match now.diff(crt.not_after()).unwrap().days {
            1 => String::from("1 day ago"),
            d => {
                format!("{} days ago", d)
            }
        },
        Ordering::Less => match now.diff(crt.not_after()).unwrap().days {
            1 => String::from("in 1 day"),
            d => {
                format!("in {} days", d)
            }
        },
        Ordering::Equal => String::from("right now"),
    };
    format!("{cn} - expires {ex} (originally {orig} days)")
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

fn get_cn(crt: &openssl::x509::X509) -> Option<String> {
    let mut cn = crt.subject_name().entries_by_nid(Nid::COMMONNAME);
    if let Some(entry) = cn.next() {
        return Some(format!("{}", entry.data().as_utf8().unwrap()));
    }
    None
}
