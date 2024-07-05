use crate::KeyType;
use path_absolutize::*;
use shellexpand;
use std::fs::create_dir_all;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub fn ca_pkey(base_dir: &str, key_type: KeyType) -> String {
    match key_type {
        KeyType::Rsa(_) => {
            format!("{base_dir}/authority.pem")
        }
        _ => {
            format!("{base_dir}/authority.{}.pem", key_type.to_string())
        }
    }
}
pub fn ca_crt(base_dir: &str, key_type: KeyType) -> String {
    match key_type {
        KeyType::Rsa(_) => format!("{base_dir}/authority.crt"),
        _ => {
            format!("{base_dir}/authority.{}.crt", key_type.to_string())
        }
    }
}

pub fn cert_pkey(base_dir: &str, name: &str, key_type: KeyType) -> String {
    match key_type {
        KeyType::Rsa(_) => {
            format!("{base_dir}/{name}/{name}.pem")
        }
        _ => {
            format!("{base_dir}/{name}/{name}.{}.pem", key_type.to_string())
        }
    }
}
pub fn cert_csr(base_dir: &str, name: &str, key_type: KeyType) -> String {
    match key_type {
        KeyType::Rsa(_) => {
            format!("{base_dir}/{name}/{name}.csr")
        }
        _ => {
            format!("{base_dir}/{name}/{name}.{}.csr", key_type.to_string())
        }
    }
}
pub fn cert_crt(base_dir: &str, name: &str, key_type: KeyType) -> String {
    match key_type {
        KeyType::Rsa(_) => {
            format!("{base_dir}/{name}/{name}.crt")
        }
        _ => {
            format!("{base_dir}/{name}/{name}.{}.crt", key_type.to_string())
        }
    }
}

pub fn intermediate_pkey(base_dir: &str, name: &str, key_type: KeyType) -> String {
    match key_type {
        KeyType::Rsa(_) => {
            format!("{base_dir}/intermediates/{name}/{name}.pem")
        }
        _ => {
            format!(
                "{base_dir}/intermediates/{name}/{name}.{}.pem",
                key_type.to_string()
            )
        }
    }
}
pub fn intermediate_csr(base_dir: &str, name: &str, key_type: KeyType) -> String {
    match key_type {
        KeyType::Rsa(_) => {
            format!("{base_dir}/intermediates/{name}/{name}.csr")
        }
        _ => {
            format!(
                "{base_dir}/intermediates/{name}/{name}.{}.csr",
                key_type.to_string()
            )
        }
    }
}
pub fn intermediate_crt(base_dir: &str, name: &str, key_type: KeyType) -> String {
    match key_type {
        KeyType::Rsa(_) => {
            format!("{base_dir}/intermediates/{name}/{name}.crt")
        }
        _ => {
            format!(
                "{base_dir}/intermediates/{name}/{name}.{}.crt",
                key_type.to_string()
            )
        }
    }
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
        false => Path::new(path)
            .parent()
            .unwrap_or_else(|| Path::new("/"))
            .to_str()
            .unwrap_or("/"),
    };

    create_dir_all(dir).unwrap();
    let mut permissions = std::fs::metadata(dir).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(dir, permissions).unwrap();
}
