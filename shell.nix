# nix/rust.nix
{ }:

let
    moz_overlay = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
    nixpkgs = import <nixpkgs> { overlays = [ moz_overlay ]; };
in
let
  pkgs = nixpkgs;
  channel = "nightly";
  date = "2020-10-16";
  targets = [ ];
  chan = (pkgs.rustChannelOfTargets channel date targets
         ).override {
           extensions = [ "clippy-preview" ];
         };
  # chan = nixpkgs.latest.rustChannels.stable.rust;
in
with pkgs;
stdenv.mkDerivation {
  name = "moz_overlay_shell";
  buildInputs = [
    chan
    openssl
    pkgconfig
    zlib
  ];
}

