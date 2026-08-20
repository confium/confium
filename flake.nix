{
  description = "Confium Development Environment";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = { nixpkgs.follows = "nixpkgs"; };
    };
    crane.url = "github:ipetkov/crane";
  };
  outputs =
    { self, nixpkgs, rust-overlay, crane, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      cwd = builtins.toString ./.;
      overlays = [ rust-overlay.overlays.default ];
      pkgs = import nixpkgs { inherit system overlays; };
      rust = pkgs.rust-bin.fromRustupToolchainFile "${cwd}/rust-toolchain.toml";
      craneLib = (crane.mkLib pkgs).overrideToolchain rust;
      # The FFI cdylib (libconfium.so / .dylib) that plugin hosts load.
      libconfium = craneLib.buildPackage {
        src = craneLib.cleanCargoSource ./.;
        strictDeps = true;
        cargoExtraArgs = "--package confium-core";
        copyLibs = true;
        doCheck = false; # the workspace test suite runs in main CI
      };
    in
    with pkgs; {
      devShells.default = clangStdenv.mkDerivation {
        name = "rust";
        nativeBuildInputs = [
          binutils
          cargo-release
          clangStdenv
          git-cliff # For generating changelog from git commit messages
          openssl
          openssl.dev
          rust
          rust-analyzer
          cargo-watch
          cmake
        ];
        RUST_SRC_PATH = "${rust}/lib/rustlib/src/rust/library";
        OPENSSL_DIR = "${openssl.bin}/bin";
        OPENSSL_LIB_DIR = "${openssl.out}/lib";
        OPENSSL_INCLUDE_DIR = "${openssl.out.dev}/include";
      };
      packages = {
        default = libconfium;
        inherit libconfium;
      };
    });
}
