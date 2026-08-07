// Confium command-line tool — entry point.
//
// Parses arguments with `clap` and dispatches to the matching command
// in `commands::*`. Nine commands are wired through the dispatcher;
// their implementation status is documented per-command.
//
// Functional commands (real implementation, unit-tested):
//   version, remove, list, info, search, trust, config
//
// Stub commands (skeleton in place; blocked on `confium-net` for
// HTTP fetching, which lands separately):
//   install, update
//
// See `crates/confium-cli/src/commands/*.rs` for per-command status.

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
        Commands::Completions(args) => commands::completions::run(args),

        // Product-umbrella subcommands.
        Commands::Threshold(cmd) => commands::threshold::run(cmd),
        Commands::Transparency(cmd) => commands::transparency::run(cmd),
        Commands::Pki(cmd) => commands::pki::run(cmd),
        Commands::Keyless(cmd) => commands::keyless::run(cmd),
        Commands::Privacy(cmd) => commands::privacy::run(cmd),
        Commands::Verify(cmd) => commands::verify::run(cmd),
    }
}
