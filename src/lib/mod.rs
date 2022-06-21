pub mod cert;
pub mod ops;
pub mod path;
pub mod pkey;
pub mod req;
pub mod root;

#[derive(Clone, Copy)]
pub enum KeyType {
    Ecdsa,
    Rsa(u32),
}

impl ToString for KeyType {
    fn to_string(&self) -> String {
        match self {
            KeyType::Rsa(_) => String::from("rsa"),
            KeyType::Ecdsa => String::from("ecdsa"),
        }
    }
}
