use crate::path;
use crate::KeyType;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::symm::Cipher;
use std::fs::{read, write, File};
use std::os::unix::fs::PermissionsExt;

pub fn generate_pkey(key_type: KeyType) -> PKey<Private> {
    match key_type {
        KeyType::Ecdsa => PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::SECP384R1).unwrap()).unwrap(),
        )
        .unwrap(),
        KeyType::Rsa(bits) => PKey::from_rsa(Rsa::generate(bits).unwrap()).unwrap(),
    }
}

pub fn save_pkey(path: &str, key: &PKey<Private>, password: Option<String>) {
    println!("{}", path);
    path::ensure_dir(path);

    let pem_encoded = match password {
        Some(pass) => {
            // AES-256-GCM is recommended by this StackOverflow answer, but not supported in
            // this function. AES-256-CBC is the alternative reccomendation and is supported
            // https://stackoverflow.com/a/22958889
            key.private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), pass.as_bytes())
                .unwrap()
        }
        None => key.private_key_to_pem_pkcs8().unwrap(),
    };
    let file = File::create(path).unwrap();
    let mut permissions = file.metadata().unwrap().permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions).unwrap();
    write(path, pem_encoded).unwrap();
}

pub fn read_pkey(path: &str, password: Option<String>) -> PKey<Private> {
    match password {
        Some(pass) => {
            PKey::private_key_from_pem_passphrase(&read(path).unwrap(), pass.as_bytes()).unwrap()
        }
        None => PKey::private_key_from_pem(&read(path).unwrap()).unwrap(),
    }
}
