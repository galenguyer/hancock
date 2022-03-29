use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Private};
use openssl::x509::{X509Name, X509Req};

use std::fs::{read, write};

use crate::path;

pub fn generate_req(
    common_name: &Option<String>,
    country: &Option<String>,
    state: &Option<String>,
    locality: &Option<String>,
    organization: &Option<String>,
    organizational_unit: &Option<String>,
    pkey: &PKey<Private>,
) -> X509Req {
    let mut x509req_builder = X509Req::builder().unwrap();

    x509req_builder.set_pubkey(pkey).unwrap();
    x509req_builder.set_version(0).unwrap();

    let mut x509_name_builder = X509Name::builder().unwrap();
    if let Some(cn) = common_name {
        x509_name_builder
            .append_entry_by_nid(Nid::COMMONNAME, cn)
            .unwrap();
    }
    if let Some(c) = country {
        x509_name_builder
            .append_entry_by_nid(Nid::COUNTRYNAME, c)
            .unwrap();
    }
    if let Some(s) = state {
        x509_name_builder
            .append_entry_by_nid(Nid::STATEORPROVINCENAME, s)
            .unwrap();
    }
    if let Some(l) = locality {
        x509_name_builder
            .append_entry_by_nid(Nid::LOCALITYNAME, l)
            .unwrap();
    }
    if let Some(o) = organization {
        x509_name_builder
            .append_entry_by_nid(Nid::ORGANIZATIONNAME, o)
            .unwrap();
    }
    if let Some(ou) = organizational_unit {
        x509_name_builder
            .append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, ou)
            .unwrap();
    }
    let x509_name = x509_name_builder.build();
    x509req_builder.set_subject_name(&x509_name).unwrap();

    let digest_algorithm = match pkey.id() {
        Id::RSA => MessageDigest::sha256(),
        Id::EC => MessageDigest::sha384(),
        _ => MessageDigest::sha256(),
    };

    x509req_builder.sign(pkey, digest_algorithm).unwrap();

    x509req_builder.build()
}

pub fn save_req(path: &str, req: &X509Req) {
    println!("{}", path);
    path::ensure_dir(path);
    write(path, req.to_pem().unwrap()).unwrap();
}

pub fn read_req(path: &str) -> X509Req {
    X509Req::from_pem(&read(path).unwrap()).unwrap()
}
