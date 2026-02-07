{ system ? builtins.currentSystem }:
let
  nixpkgs = fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/d351d0653aeb7877273920cd3e823994e7579b0b.tar.gz";
    sha256 = "049hhh8vny7nyd26dfv7i962jpg18xb5bg6cv126b8akw5grb0dg";
  };
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
