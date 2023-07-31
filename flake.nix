{
  description = "Confium Development Environment";
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    cargo2nix.url = "github:cargo2nix/cargo2nix";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = { nixpkgs.follows = "nixpkgs"; };
    };
    devshell.url = "github:numtide/devshell/main";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };
  outputs =
    { self, nixpkgs, cargo2nix, rust-overlay, flake-utils, devshell, flake-compat, ... }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      cwd = builtins.toString ./.;
      overlays = map (x: x.overlays.default) [
        devshell
        cargo2nix
        rust-overlay
      ];
      pkgs = import nixpkgs { inherit system overlays; };
      toolchain = pkgs.rust-bin.fromRustupToolchainFile "${cwd}/rust-toolchain";
      rustPkgs = pkgs.rustBuilder.makePackageSet {
        packageFun = import ./Cargo.nix;
        rustToolchain = toolchain;
      };
    in
    rec {

      packages = {
        # nix build .#packages.aarch64-darwin.libconfium
        # nix build .#libconfium
        libconfium = (rustPkgs.workspace.confium { }).out;
        default = packages.libconfium;
      };
      defaultPackage = packages.default;

      # nix develop
      devShell = pkgs.devshell.mkShell {
        env = [
          {
            name = "RUST_SRC_PATH";
            value = "${toolchain}/lib/rustlib/src/rust/library";
          }
          {
            name = "LIBRARY_PATH";
            value = "${pkgs.libiconv}/lib";
          }
        ];
        packages = with pkgs; [
          clang
          cmake
          git-cliff # For generating changelog from git commit messages
          # toolchain
        ] ++ (with rustPkgs.pkgs; [
          rustup
        ]);
      };
    });
}
