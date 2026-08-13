{
  description = "Placeholder website";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ self, flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      imports = [
        inputs.treefmt-nix.flakeModule
      ];

      perSystem =
        { self', pkgs, ... }:

        let
          packageVersion = (./package.json |> builtins.readFile |> builtins.fromJSON).version;
        in
        {
          treefmt = {
            programs.nixfmt.enable = true;
            programs.deadnix.enable = true;
          };

          devShells.default = pkgs.mkShell {
            packages = [
              pkgs.nodejs
              pkgs.pnpm_11
            ];
          };

          packages.default = (pkgs.callPackage ./package.nix { }).overrideAttrs {
            version = "${packageVersion}-${self.shortRev or self.dirtyShortRev or "dirty-norev"}";
            __intentionallyOverridingVersion = true;
          };

          checks.pnpm = pkgs.stdenv.mkDerivation {
            pname = "omeduoweb-pnpm-checked";

            inherit (self'.packages.default)
              version
              src
              pnpmDeps
              nativeBuildInputs
              ;

            installPhase = ''
              pnpm run check > $out
            '';
          };
        };
    };
}
