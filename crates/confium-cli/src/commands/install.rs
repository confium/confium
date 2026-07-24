// `confium install <plugin>[@version]` — not yet implemented.
//
// Stub per `TODO.roadmap/07-cli-tools.md`. The real implementation will
// resolve the plugin against the registry, verify the publisher's trust
// root, and stage the artifact into the local plugin directory.

use crate::cli::InstallArgs;

pub fn run(args: InstallArgs) -> ! {
    eprintln!("confium install: not yet implemented");
    eprintln!("See TODO.roadmap/07-cli-tools.md for the design.");
    eprintln!("Args received: {args:?}");
    std::process::exit(2);
}
