// `confium update [<plugin>]` — not yet implemented.

use crate::cli::UpdateArgs;

pub fn run(args: UpdateArgs) -> ! {
    eprintln!("confium update: not yet implemented");
    eprintln!("See TODO.roadmap/07-cli-tools.md for the design.");
    eprintln!("Args received: {args:?}");
    std::process::exit(2);
}
