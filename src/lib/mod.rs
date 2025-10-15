pub mod cert;
pub mod ops;
pub mod path;
pub mod pkey;
pub mod req;
pub mod root;

#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    Ecdsa,
    Rsa(u32),
}

impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyType::Rsa(_) => write!(f, "rsa"),
            KeyType::Ecdsa => write!(f, "ecdsa"),
        }
    }
}
