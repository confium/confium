// Confium command-line tool — entry point.
//
// Parses arguments with `clap` and dispatches to the matching command in
// `commands::*`. Only `version` is implemented today; every other command
// prints a "not yet implemented" notice and exits with status 2 so callers
// can tell scaffolding apart from real behavior.
//
// Command surface design: `TODO.roadmap/07-cli-tools.md`.

mod cli;
mod commands;

use clap::Parser;

use cli::{Cli, Commands};

fn main() {
    let cli = Cli::parse();
    dispatch(cli);
}

/// Route a parsed `Cli` to the matching command implementation.
///
/// Split out from `main` so the dispatch shape is easy to read and
/// future integration tests can exercise it directly.
fn dispatch(cli: Cli) {
    match cli.command {
        Commands::Install(args) => commands::install::run(args),
        Commands::Remove(args) => commands::remove::run(args),
        Commands::Update(args) => commands::update::run(args),
        Commands::List(args) => commands::list::run(args),
        Commands::Info(args) => commands::info::run(args),
        Commands::Search(args) => commands::search::run(args),
        Commands::Trust(args) => commands::trust::run(args),
        Commands::Config(args) => commands::config::run(args),
        Commands::Version => commands::version::run(),
    }
}
