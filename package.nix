{
  lib,
  stdenv,
  pnpm_11,
  fetchPnpmDeps,
  pnpmConfigHook,
  nodejs,
  makeWrapper,
}:

let
  pnpm = pnpm_11;

  inherit (lib) getExe;
in
stdenv.mkDerivation (finalAttrs: {
  pname = "omeduoweb";
  version = "unstable";

  __structuredAttrs = true;
  strictDeps = true;

  src = ./.;

  nativeBuildInputs = [
    nodejs
    pnpm
    pnpmConfigHook
    makeWrapper
  ];

  pnpmDeps = fetchPnpmDeps {
    inherit (finalAttrs) pname version src;
    inherit pnpm;
    fetcherVersion = 4;
    hash = "sha256-2mOHW+ONyX1ksQaeFhHRpH9urUIEd87mkFk6M4FSi1M=";
  };

  buildPhase = ''
    runHook preBuild
    pnpm run build
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    cp -r build $out/
    makeWrapper ${getExe nodejs} $out/bin/omeduoweb --append-flag "$out"
    runHook postInstall
  '';

  meta = {
    description = "";
    homepage = "https://git.bartoostveen.nl/bart/omeduoweb";
    license = lib.licenses.mit;
    maintainers = with lib.maintainers; [ bartoostveen ];
    mainProgram = "omeduoweb";
    platforms = lib.platforms.all;
  };
})
