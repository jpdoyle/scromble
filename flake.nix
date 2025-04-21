{
  description = "A devShell example";

  inputs = {
    nixpkgs.url      = github:nixos/nixpkgs/nixos-24.11;
    flake-utils.url  = github:numtide/flake-utils;
  };

  outputs = { self, nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      with pkgs;
      rec {
        devShell = mkShell {
          buildInputs = [ cargo rustfmt clippy ];

          RUST_BACKTRACE="full";
        };
        packages.scromble = rustPlatform.buildRustPackage rec {
          name = "scromble-${version}";
          version = if (self ? rev) then self.rev else "dirty";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
        };
        packages.default = packages.scromble;
      }
    );
}


