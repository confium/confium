// `confium list` — not yet implemented.

use crate::cli::ListArgs;

pub fn run(args: ListArgs) -> ! {
    eprintln!("confium list: not yet implemented");
    eprintln!("See TODO.roadmap/07-cli-tools.md for the design.");
    eprintln!("Args received: {args:?}");
    std::process::exit(2);
}
