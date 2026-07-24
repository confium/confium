// `confium trust list|add|remove` — not yet implemented.
//
// `trust` carries a nested subcommand (`TrustAction`). The dispatcher here
// only owns the routing; the actual trust-store mutation logic lives in
// `confium-store` and will be wired in once that crate exposes the needed
// operations.

use crate::cli::{TrustAction, TrustArgs};

pub fn run(args: TrustArgs) -> ! {
    match args.action {
        TrustAction::List => {
            eprintln!("confium trust list: not yet implemented");
        }
        TrustAction::Add(add) => {
            eprintln!("confium trust add: not yet implemented");
            eprintln!("Args received: {add:?}");
        }
        TrustAction::Remove(remove) => {
            eprintln!("confium trust remove: not yet implemented");
            eprintln!("Args received: {remove:?}");
        }
    }
    eprintln!("See TODO.roadmap/07-cli-tools.md for the design.");
    std::process::exit(2);
}
