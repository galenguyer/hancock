use std::path::Path;
use clap::{Parser, Subcommand};

use hancock::ops::*;

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
    List(List),
}

fn main() {
    let env_file = match Path::new(".env").exists() {
        true => Some(String::from(".env")),
        false => {
            match Path::new(&dirs::home_dir().unwrap()).join(".hancock.conf").exists() {
                true => Some(Path::new(&dirs::home_dir().unwrap()).join(".hancock.conf").to_str().unwrap().to_owned()),
                false => None
            }
        }
    };

    if let Some(file) = env_file {
        dotenvy::from_path(Path::new(&file)).ok();
    }

    #[cfg(not(debug_assertions))]
    let cli = Cli::parse();
    #[cfg(debug_assertions)]
    let cli = dbg!(Cli::parse());

    match cli.command {
        Commands::Init(args) => init(args),
        Commands::Issue(args) => issue(args),
        Commands::List(args) => list(args),
    }
}
