use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Init(Init),
    Issue(Issue),
}

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
