// `confium remove <plugin>` — not yet implemented.

use crate::cli::RemoveArgs;

pub fn run(args: RemoveArgs) -> ! {
    eprintln!("confium remove: not yet implemented");
    eprintln!("See TODO.roadmap/07-cli-tools.md for the design.");
    eprintln!("Args received: {args:?}");
    std::process::exit(2);
}
