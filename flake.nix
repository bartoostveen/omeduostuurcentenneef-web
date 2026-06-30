{
  description = "Generic devshell flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";

    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    bun2nix = {
      url = "github:nix-community/bun2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  nixConfig = {
    extra-substituters = [
      "https://cache.nixos.org"
      "https://nix-community.cachix.org"
    ];
    extra-trusted-public-keys = [
      "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
      "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
    ];
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];

      imports = [
        inputs.treefmt-nix.flakeModule
      ];

      perSystem =
        {
          pkgs,
          system,
          self',
          ...
        }:

        let
          deps = with pkgs; [
            nodejs_24
            bun
          ];
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              inputs.bun2nix.overlays.default
            ];
          };

          treefmt = {
            programs.nixfmt.enable = true;
            programs.deadnix = {
              enable = true;
              excludes = [ "bun.nix" ];
            };
          };

          devShells.default = pkgs.mkShell {
            packages = deps;
          };

          packages = {
            default = pkgs.callPackage ./package.nix { };
            inherit (self'.packages.default) format;
          };

          apps.bun2nix-update = {
            type = "app";
            program = pkgs.writeShellApplication {
              name = "bun2nix-update";
              runtimeInputs = deps;
              text = ''
                bun run bun2nix:update
              '';
            };
          };
        };
    };
}
