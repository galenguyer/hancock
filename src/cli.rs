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
    let cli = dbg!(Cli::parse());

    match cli.command {
        Commands::Init(args) => init(args),
        Commands::Issue(args) => issue(args),
        Commands::List(args) => list(args),
    }
}
