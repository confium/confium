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
      devShell = pkgs.devshell.mkShell {
        env = [
          {
            name = "RUST_SRC_PATH";
            value = "${rust}/lib/rustlib/src/rust/library";
          }
          {
            name = "LIBRARY_PATH";
            value = "${libiconv}/lib";
          }
        ];
        packages = [
          cargo-release
          cargo-watch
          clang
          cmake
          git-cliff # For generating changelog from git commit messages
          rust
          rust-analyzer
        ];
      };
    });
}
