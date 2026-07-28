// Confium plugin publishing tool — entry point.
//
// Parses arguments, loads the artifact via the FFI contract, computes
// the SHA-256, generates `manifest.toml`, signs it with the publisher's
// PGP key, and writes a directory tree ready to drop into the registry
// repo.
//

use std::path::Path;
use std::process::ExitCode;

use clap::Parser;

use confium_publish::PublishArgs;
use confium_publish::{
    build, open_library, paths_for, query_interfaces, query_metadata, resolve_algorithms,
    resolve_interfaces, sha256_of_file, sign_manifest, to_toml, write_tree,
};

/// Default minimum Confium runtime version written into every manifest.
/// Bumped when the plugin contract gains a hard requirement.
const DEFAULT_MIN_RUNTIME: &str = "0.3.0";

fn main() -> ExitCode {
    let args = PublishArgs::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("confium-publish: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Top-level orchestration. Split out from `main` so integration tests
/// can drive it without re-parsing argv.
fn run(args: &PublishArgs) -> Result<(), String> {
    if !args.artifact.exists() {
        return Err(format!(
            "artifact not found at '{}'",
            args.artifact.display()
        ));
    }

    // --- Query FFI metadata + interfaces --------------------------------
    let lib = open_library(&args.artifact).map_err(|e| format!("load artifact: {e}"))?;
    let ffi_metadata = query_metadata(&lib)
        .map_err(|e| format!("query cfmp_metadata: {e}"))?
        .unwrap_or_default();
    let ffi_interfaces =
        query_interfaces(&lib).map_err(|e| format!("query cfmp_query_interfaces: {e}"))?;

    // --- Resolve effective fields (CLI overrides FFI) -------------------
    let name = args
        .name
        .clone()
        .or(ffi_metadata.name.clone())
        .ok_or_else(|| {
            "plugin name required: pass --name or build cfmp_metadata into the artifact".to_string()
        })?;
    let version = args
        .version
        .clone()
        .or(ffi_metadata.version.clone())
        .ok_or_else(|| {
            "plugin version required: pass --version or build cfmp_metadata into the artifact"
                .to_string()
        })?;

    let interfaces = resolve_interfaces(ffi_interfaces.as_deref(), args.interfaces.as_deref())
        .map_err(|e| format!("resolve interfaces: {e}"))?;
    let algorithms = resolve_algorithms(args.algorithms.as_deref())
        .map_err(|e| format!("resolve algorithms: {e}"))?;

    // --- Compute artifact digest + URL ----------------------------------
    let sha256_hex = sha256_of_file(&args.artifact).map_err(|e| format!("compute sha256: {e}"))?;
    let artifact_size = std::fs::metadata(&args.artifact)
        .map_err(|e| format!("stat artifact: {e}"))?
        .len();
    let artifact_url = artifact_url(args.artifact_base.as_deref(), &args.artifact);

    // --- Build + serialize the manifest ---------------------------------
    let input = confium_publish::ManifestInput {
        metadata: &ffi_metadata,
        publisher: &args.publisher,
        cli_name: Some(&name),
        cli_version: Some(&version),
        interfaces: &interfaces,
        algorithms: &algorithms,
        artifact_url: artifact_url.clone(),
        artifact_size,
        artifact_sha256: sha256_hex.clone(),
        contract_version: 0,
        min_runtime: DEFAULT_MIN_RUNTIME,
        mirrors: Vec::new(),
    };
    let manifest_model = build(&input);
    let manifest_toml = to_toml(&manifest_model).map_err(|e| format!("serialize manifest: {e}"))?;

    // --- Lay out the output tree ----------------------------------------
    let output_root =
        std::env::current_dir().map_err(|e| format!("determine output root (cwd): {e}"))?;
    let paths = paths_for(&output_root, &name, &version, &args.publisher);

    write_tree(
        &paths,
        &manifest_toml,
        &args.artifact,
        &sha256_hex,
        b"", // signature filled below for non-dry-run
        args.dry_run,
    )
    .map_err(|e| format!("write tree: {e}"))?;

    // --- Sign the manifest on disk --------------------------------------
    if !args.dry_run {
        let signature = sign_manifest(&paths.manifest, &args.signing_key.to_string_lossy(), false)
            .map_err(|e| format!("sign manifest: {e}"))?;
        std::fs::write(&paths.signature, &signature)
            .map_err(|e| format!("write signature: {e}"))?;
    }

    // --- Report ----------------------------------------------------------
    print_report(args, &name, &version, &paths, &sha256_hex, &manifest_toml);
    // Keep the library alive past the report so any borrowed FFI data
    // referenced during serialization is still valid. (It is already
    // copied out by this point, but the explicit drop documents intent.)
    drop(lib);
    Ok(())
}

/// Compose the canonical artifact URL from the `--artifact-base` prefix
/// and the artifact's basename.
fn artifact_url(base: Option<&str>, artifact: &Path) -> String {
    let basename = artifact
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "artifact".to_string());
    match base {
        Some(b) => {
            let b = b.trim_end_matches('/');
            format!("{b}/{basename}")
        }
        None => basename,
    }
}

fn print_report(
    args: &PublishArgs,
    name: &str,
    version: &str,
    paths: &confium_publish::OutputPaths,
    sha256_hex: &str,
    manifest_toml: &str,
) {
    if args.dry_run {
        println!("[dry-run] would write:");
    } else {
        println!("wrote:");
    }
    println!("  {}/", paths.dir.display());
    println!("    manifest.toml");
    println!("    artifact.sha256");
    println!("    sigs/{}.asc", args.publisher);
    println!();
    println!("plugin:    {name} {version}");
    println!("publisher: {}", args.publisher);
    println!("sha256:    {sha256_hex}");
    println!();
    if args.dry_run {
        println!("--- manifest.toml (preview) ---");
        println!("{manifest_toml}");
        println!("--- end preview ---");
        println!();
    }
    println!("Next: open a PR adding this directory to");
    println!("  https://github.com/confium/registry/tree/main/plugins/{name}/{version}/");
    println!("Registry: {}", args.registry);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_url_joins_base_and_basename() {
        let got = artifact_url(
            Some("https://example.com/releases/v1/"),
            Path::new("/build/libfoo.dylib"),
        );
        assert_eq!(got, "https://example.com/releases/v1/libfoo.dylib");
    }

    #[test]
    fn artifact_url_basename_only_without_base() {
        let got = artifact_url(None, Path::new("/build/libfoo.dylib"));
        assert_eq!(got, "libfoo.dylib");
    }

    #[test]
    fn artifact_url_no_trailing_slash_double() {
        let got = artifact_url(Some("https://example.com/x"), Path::new("libfoo.so"));
        assert_eq!(got, "https://example.com/x/libfoo.so");
    }
}
