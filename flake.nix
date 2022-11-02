{
  description = "Confium Development Environment";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = { nixpkgs.follows = "nixpkgs"; };
    };
    devshell.url = "github:numtide/devshell/master";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };
  outputs =
    { self, nixpkgs, rust-overlay, flake-utils, devshell, flake-compat, ... }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      cwd = builtins.toString ./.;
      overlays = [ devshell.overlay rust-overlay.overlays.default ];
      pkgs = import nixpkgs { inherit system overlays; };
      rust = pkgs.rust-bin.fromRustupToolchainFile "${cwd}/rust-toolchain";
    in
    with pkgs; {
      devShell = clangStdenv.mkDerivation {
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
    });
}
