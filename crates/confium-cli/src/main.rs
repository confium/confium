// Confium command-line tool.
//
// End-user commands: install, remove, update, list, info, search, trust,
// config, version. See `TODO.roadmap/07-cli-tools.md` for the full design.
//
// Today this is a placeholder skeleton — clap-based arg parsing for a
// single `version` subcommand. Sub-commands will be added per the roadmap.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--help") | Some("-h") => print_help(),
        Some("--version") | Some("-V") => {
            println!("confium {}", env!("CARGO_PKG_VERSION"));
        }
        Some("version") => {
            println!("confium {}", env!("CARGO_PKG_VERSION"));
        }
        _ => {
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!(
        "confium {} — trust store framework",
        env!("CARGO_PKG_VERSION")
    );
    println!();
    println!("USAGE:");
    println!("    confium <COMMAND>");
    println!();
    println!("COMMANDS (planned, see TODO.roadmap/07-cli-tools.md):");
    println!("    install <plugin>[@version]     Install a plugin from the registry");
    println!("    remove <plugin>                Uninstall a plugin");
    println!("    update [<plugin>]              Update plugin(s) to latest");
    println!("    list                           List installed plugins");
    println!("    info <plugin>[@version]        Show plugin manifest details");
    println!("    search [<interface>] [<algo>]  Search the registry index");
    println!("    trust                          Manage publisher trust roots");
    println!("    config                         Edit local config");
    println!("    version                        Show version");
}
