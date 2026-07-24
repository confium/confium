// Confium plugin publishing tool.
//
// Loads a built plugin via the FFI contract, queries its metadata,
// generates a signed manifest, and opens a PR against the registry
// repository.
//
// See `TODO.roadmap/06-module-registry.md` (publishing flow) and
// `TODO.roadmap/07-cli-tools.md` (this command's CLI).
//
// Today this is a placeholder skeleton.

fn main() {
    eprintln!(
        "confium-publish {} — placeholder. See TODO.roadmap/07-cli-tools.md",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(2);
}
