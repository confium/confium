// End-to-end round-trip test for `confium-publish`.
//
// Exercises the full `run()` flow with a fake artifact (a plain file with
// no FFI symbols) and CLI overrides for every metadata field. Verifies
// the output directory tree, the SHA-256 file format, the manifest
// structure, and that `--dry-run` writes nothing.

use std::fs;
use std::path::PathBuf;

use confium_publish::{manifest, output, sign};

/// Build the CLI args the way `main` would, but pointing at a temp dir
/// as the output root. We call the lower-level helpers directly rather
/// than `run()` so the test does not depend on `current_dir()`.
fn publish_into(
    artifact: &std::path::Path,
    root: &std::path::Path,
    name: &str,
    version: &str,
    publisher: &str,
    dry_run: bool,
) -> Vec<u8> {
    // FFI is absent for the fake artifact, so metadata is empty and we
    // rely entirely on the CLI-provided name/version.
    let metadata = confium_publish::PluginMetadata::default();

    // Resolve interfaces/algorithms from CLI-shaped overrides.
    let interfaces_raw = vec!["hash:0".to_string(), "rng:0".to_string()];
    let interfaces = confium_publish::resolve_interfaces(None, Some(&interfaces_raw)).unwrap();
    let algorithms_raw = vec!["hash:SHA-256;SHA-512".to_string()];
    let algorithms = confium_publish::resolve_algorithms(Some(&algorithms_raw)).unwrap();

    // Compute the real SHA-256 of the fake artifact.
    let sha = output::sha256_of_file(artifact).unwrap();
    let size = fs::metadata(artifact).unwrap().len();

    let input = manifest::ManifestInput {
        metadata: &metadata,
        publisher,
        cli_name: Some(name),
        cli_version: Some(version),
        interfaces: &interfaces,
        algorithms: &algorithms,
        artifact_url: format!("https://example.com/releases/{name}/{version}/artifact.so"),
        artifact_size: size,
        artifact_sha256: sha.clone(),
        contract_version: 0,
        min_runtime: "0.3.0",
        mirrors: Vec::new(),
    };
    let model = manifest::build(&input);
    let toml_str = manifest::to_toml(&model).unwrap();

    let paths = output::paths_for(root, name, version, publisher);
    output::write_tree(
        &paths, &toml_str, artifact, &sha, b"", // signature separate
        dry_run,
    )
    .unwrap();

    // Sign. We always use gpg's dry-run path because integration tests
    // don't have a real publisher key; the round-trip test only verifies
    // that the sig file is written and non-empty.
    let sig = sign::sign_manifest(&paths.manifest, publisher, true).unwrap();
    if !dry_run {
        fs::write(&paths.signature, &sig).unwrap();
    }
    sig
}

fn unique_tmp(prefix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "{prefix}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    p
}

#[test]
fn round_trip_writes_full_tree_and_valid_manifest() {
    let root = unique_tmp("cfm_pub_e2e");
    let artifact = unique_tmp("cfm_pub_artifact");
    fs::write(&artifact, b"this is a fake plugin artifact").unwrap();

    publish_into(&artifact, &root, "fakeplug", "1.2.3", "testpub", false);

    let version_dir = root.join("fakeplug").join("1.2.3");
    assert!(version_dir.is_dir(), "version dir exists");
    assert!(version_dir.join("manifest.toml").is_file());
    assert!(version_dir.join("artifact.sha256").is_file());
    assert!(version_dir.join("sigs").join("testpub.asc").is_file());

    // SHA-256 file matches sha256sum format: "<hex>  <basename>".
    let sha_file = fs::read_to_string(version_dir.join("artifact.sha256")).unwrap();
    let expected_sha = sha256_via_shasum(&artifact);
    assert!(
        sha_file.contains(&expected_sha),
        "artifact.sha256 contains the shasum digest: {sha_file}"
    );
    assert!(
        sha_file.contains("cfm_pub_artifact"),
        "artifact.sha256 names the basename"
    );

    // Manifest is parseable TOML with the expected structure.
    let manifest_text = fs::read_to_string(version_dir.join("manifest.toml")).unwrap();
    let parsed: toml::Value = toml::from_str(&manifest_text).unwrap();
    let plugin = parsed.get("plugin").and_then(|v| v.as_table()).unwrap();
    assert_eq!(
        plugin.get("name").and_then(|v| v.as_str()),
        Some("fakeplug")
    );
    assert_eq!(
        plugin.get("version").and_then(|v| v.as_str()),
        Some("1.2.3")
    );
    assert_eq!(
        plugin.get("publisher").and_then(|v| v.as_str()),
        Some("testpub")
    );

    let ifaces = parsed.get("interfaces").and_then(|v| v.as_table()).unwrap();
    assert_eq!(ifaces.get("hash").and_then(|v| v.as_integer()), Some(0));
    assert_eq!(ifaces.get("rng").and_then(|v| v.as_integer()), Some(0));

    let algos = parsed.get("algorithms").and_then(|v| v.as_table()).unwrap();
    let hash_algos = algos.get("hash").and_then(|v| v.as_array()).unwrap();
    assert_eq!(hash_algos.len(), 2);

    let artifact_section = parsed.get("artifact").and_then(|v| v.as_table()).unwrap();
    assert_eq!(
        artifact_section.get("sha256").and_then(|v| v.as_str()),
        Some(expected_sha.as_str())
    );

    // Signature file is non-empty.
    let sig = fs::read(version_dir.join("sigs").join("testpub.asc")).unwrap();
    assert!(!sig.is_empty());

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_file(&artifact);
}

#[test]
fn dry_run_writes_nothing() {
    let root = unique_tmp("cfm_pub_dryrun");
    let artifact = unique_tmp("cfm_pub_dryrun_art");
    fs::write(&artifact, b"x").unwrap();

    let sig = publish_into(&artifact, &root, "dp", "0.1.0", "pub", true);
    assert!(!root.join("dp").exists(), "dry-run leaves no output dir");
    assert!(
        sig.windows(b"BEGIN PGP SIGNATURE".len())
            .any(|w| w == b"BEGIN PGP SIGNATURE")
    );

    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_file(&artifact);
}

/// Cross-check our Rust SHA-256 against the system `shasum -a 256` (or
/// `sha256sum` on Linux) so the test is independent of our own hasher.
/// On Windows we fall back to computing SHA-256 in-process via sha2
/// (no `shasum` / `sha256sum` available by default).
fn sha256_via_shasum(path: &std::path::Path) -> String {
    use std::process::Command;
    let out = if cfg!(target_os = "macos") {
        Command::new("shasum")
            .args(["-a", "256"])
            .arg(path)
            .output()
            .expect("shasum available")
    } else if cfg!(target_os = "windows") {
        let bytes = std::fs::read(path).expect("read artifact back");
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&bytes);
        return hex::encode(h.finalize());
    } else {
        Command::new("sha256sum")
            .arg(path)
            .output()
            .expect("sha256sum available")
    };
    assert!(out.status.success(), "shasum succeeded");
    let line = String::from_utf8(out.stdout).unwrap();
    line.split_whitespace().next().unwrap().to_string()
}
