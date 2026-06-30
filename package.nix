{
  bun2nix,
  lib,
  makeWrapper,
  nodejs,
  ...
}:

let
  inherit (lib) optionalString getExe;

  mkBunCmd =
    finalAttrs: startScript:
    {
      pname ? "bun-cmd",
      chDir ? false,
    }:

    bun2nix.writeBunApplication {
      inherit pname;
      inherit (finalAttrs) src bunDeps packageJson;

      dontUseBunBuild = true;
      dontUseBunCheck = true;

      startScript = (optionalString (!chDir) "cd -\n") + startScript;
    };

  mkBunX = finalAttrs: bin: mkBunCmd finalAttrs "bunx ${bin} \"$@\"" { pname = bin; };
in
bun2nix.mkDerivation (finalAttrs: {
  src = ./.;
  packageJson = ./package.json;

  bunDeps = bun2nix.fetchBunDeps {
    bunNix = ./bun.nix;
  };

  nativeBuildInputs = [
    makeWrapper
  ];

  buildPhase = ''
    runHook preBuild
    bun run build
    runHook postBuild
  '';

  passthru = {
    prettier = mkBunX finalAttrs "prettier";
    format = mkBunCmd finalAttrs "bun run format" { };
  };

  installPhase = ''
    runHook preInstall
    cp -r build $out/
    makeWrapper ${getExe nodejs} $out/bin/omeduostuurcentenneef-web --append-flag "$out"
    runHook postInstall
  '';
})
