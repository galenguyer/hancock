use crate::KeyType;
use path_absolutize::*;
use shellexpand;
use std::path::Path;
use std::fs::create_dir_all;

pub fn ca_pkey(base_dir: &str, key_type: KeyType) -> String {
    format!("{}/authority.{}.pem", base_dir, key_type.to_string())
}

pub fn base_dir(raw_base: &str) -> String {
    Path::new(&shellexpand::tilde(&raw_base).to_string())
    .absolutize()
    .unwrap()
    .to_str()
    .unwrap()
    .to_string()
}

pub fn ensure_dir(path: &str) {
    let dir = match Path::new(path).is_dir() {
        true => path,
        false => Path::new(path).parent().unwrap_or(Path::new("/")).to_str().unwrap_or("/"),
    };

    create_dir_all(dir).unwrap();
}
