// `confium config edit|show|set|get` — not yet implemented.
//
// Like `trust`, `config` carries a nested subcommand. The real
// implementation will read/write the local TOML config described in
// `TODO.roadmap/07-cli-tools.md` (Configuration section).

use crate::cli::{ConfigAction, ConfigArgs};

pub fn run(args: ConfigArgs) -> ! {
    match args.action {
        ConfigAction::Edit => {
            eprintln!("confium config edit: not yet implemented");
        }
        ConfigAction::Show => {
            eprintln!("confium config show: not yet implemented");
        }
        ConfigAction::Set(set) => {
            eprintln!("confium config set: not yet implemented");
            eprintln!("Args received: {set:?}");
        }
        ConfigAction::Get(get) => {
            eprintln!("confium config get: not yet implemented");
            eprintln!("Args received: {get:?}");
        }
    }
    eprintln!("See TODO.roadmap/07-cli-tools.md for the design.");
    std::process::exit(2);
}
