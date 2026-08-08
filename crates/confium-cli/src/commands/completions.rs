//! `confium completions` — generate shell completion scripts.
//!
//! Emits a completion script for the requested shell to stdout. The
//! script is suitable for `source <(confium completions bash)` or for
//! installing into the shell's standard completion directory.

use crate::cli::CompletionsArgs;
use clap::CommandFactory;
use clap_complete::{Shell, generate};

pub fn run(args: CompletionsArgs) {
    let mut cmd = crate::cli::Cli::command();
    let shell = match args.shell.as_str() {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        "elvish" => Shell::Elvish,
        "powershell" => Shell::PowerShell,
        other => {
            eprintln!("confium completions: unknown shell {other}");
            std::process::exit(1);
        }
    };
    generate(shell, &mut cmd, "confium", &mut std::io::stdout());
}
