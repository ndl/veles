{ nixpkgs ? <nixpkgs>, system ? builtins.currentSystem }:
let
  pkgs = import nixpkgs {
    overlays = [];
    config = {};
    inherit system;
  };
  libtpms = pkgs.libtpms.overrideAttrs(oldAttrs: {
    patches = oldAttrs.patches or [] ++ [
      ./nixpkgs/libtpms/allow-extra-disabling.patch
    ];
  });
  swtpm = (pkgs.swtpm.override { inherit libtpms; }).overrideAttrs(oldAttrs: {
    doCheck = false;
  });
in pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    (bats.withLibraries (p: [
      p.bats-support
      p.bats-assert
      p.bats-file
      p.bats-detik
    ]))
    bubblewrap
    keyutils
    markdownlint-cli2
    swtpm
    tpm2-tools
  ];
  buildInputs = with pkgs; [
    keyutils.dev
    keyutils.lib
    zig
  ];
 }
