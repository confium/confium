// `confium version` — fully implemented.
//
// Prints the CLI's own version (from `CARGO_PKG_VERSION`). The Confium
// engine (`confium-core`) keeps its version in a private `const VERSION`;
// since it is not re-exported, the CLI reports only its own build version
// today. When the engine exposes a public version accessor, link it in.

/// Build the human-readable version string used by both `run` and tests.
///
/// Kept as a pure function (no I/O) so the unit test can assert on its
/// output without spawning the binary.
pub fn version_string() -> String {
    format!("confium {}", env!("CARGO_PKG_VERSION"))
}

pub fn run() {
    println!("{}", version_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_string_contains_pkg_version() {
        let expected = env!("CARGO_PKG_VERSION");
        let got = version_string();
        assert!(
            got.contains(expected),
            "version_string {got:?} should contain CARGO_PKG_VERSION {expected:?}"
        );
    }

    #[test]
    fn version_string_is_prefixed_with_name() {
        let got = version_string();
        assert!(
            got.starts_with("confium "),
            "version_string {got:?} should start with 'confium '"
        );
    }
}
