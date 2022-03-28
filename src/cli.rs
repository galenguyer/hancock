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
}

#[derive(Args, Debug)]
pub struct Init {
    /// Base directory to store certificates
    #[clap(long, default_value = "~/.hancock", env = "CA_BASE_DIR")]
    pub base_dir: String,

    /// Algorithm to generate private keys ('RSA' or 'ECDSA')
    #[clap(long, default_value = "RSA", validator = validate_key_type)]
    pub key_type: String,

    /// Length to use when generating an RSA key. Ignored for ECDSA
    #[clap(long, default_value_t = 4096)]
    pub key_length: u32,

    /// Lifetime in days of the generated certificate
    #[clap(long, default_value_t = 365 * 10)]
    pub lifetime: u32,

    #[clap(long)]
    pub common_name: Option<String>,

    #[clap(long)]
    pub country: Option<String>,

    #[clap(long)]
    pub state: Option<String>,

    #[clap(long)]
    pub locality: Option<String>,

    #[clap(long)]
    pub organization: Option<String>,

    #[clap(long)]
    pub organizational_unit: Option<String>,

    #[clap(long, env = "CA_PASSWORD")]
    pub password: Option<String>,

    #[clap(long)]
    pub no_password: bool,
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
