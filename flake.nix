{
  description = "A devShell example";

  inputs = {
    nixpkgs.url      = github:nixos/nixpkgs/nixos-21.11;
    flake-utils.url  = github:numtide/flake-utils;
    rust-overlay.url = github:oxalica/rust-overlay;
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in
      with pkgs;
      {
        devShell = mkShell {
          buildInputs = [
            openssl
            pkgconfig
            rust-bin.stable.latest.default
          ];

          RUST_BACKTRACE="full";
        };
      }
    );
}


