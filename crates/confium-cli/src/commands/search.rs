// `confium search [<interface>] [<algorithm>]` — not yet implemented.

use crate::cli::SearchArgs;

pub fn run(args: SearchArgs) -> ! {
    eprintln!("confium search: not yet implemented");
    eprintln!("See TODO.roadmap/07-cli-tools.md for the design.");
    eprintln!("Args received: {args:?}");
    std::process::exit(2);
}
