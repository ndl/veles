{
  callPackage,
  fetchFromGitHub,
  keyutils,
  lib,
  nix-gitignore,
  stdenv,
  zig_0_15,
  debug ? false,
}:
stdenv.mkDerivation (finalAttrs: {
  pname = "veles";
  version = "0.3.5";

  src = [
    ./build.zig
    ./build.zig.zon
    ./src
  ];

  unpackPhase = ''
    for srcFile in $src; do
      cp -R $srcFile $(stripHash $srcFile)
    done
  '';

  nativeBuildInputs = [
    zig_0_15.hook
  ];

  buildInputs = [
    keyutils.dev
    keyutils.lib
  ];

  zigBuildFlags = if debug then [ "--release=off" "-Doptimize=Debug" ] else [ "--release=small" ];

  postPatch = ''
    ln -s ${callPackage ./build.zig.zon.nix { }} $ZIG_GLOBAL_CACHE_DIR/p
  '';

  meta = {
    description = "ZFS TPM-based encryption tool";
    homepage = "https://github.com/ndl/veles";
    license = lib.licenses.gpl3Only;
    maintainers = with lib.maintainers; [ ndl ];
    mainProgram = "veles";
    inherit (zig_0_15.meta) platforms;
  };
})
