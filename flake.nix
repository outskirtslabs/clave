{
  description = "dev env";
  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1"; # tracks nixpkgs unstable branch
    devshell.url = "github:numtide/devshell";
    devshell.inputs.nixpkgs.follows = "nixpkgs";
    devenv.url = "github:ramblurr/nix-devenv";
    devenv.inputs.nixpkgs.follows = "nixpkgs";
    clj-helpers.url = "github:outskirtslabs/clojure-nix-locker-helpers";
    clj-helpers.inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs =
    inputs@{
      self,
      devenv,
      devshell,
      clj-helpers,
      ...
    }:
    let
      package =
        pkgs:
        clj-helpers.lib.mkCljLib {
          inherit pkgs;
          name = "clave";
          version = "0.0.0";
          src = ./.;
          prefetchAliases = [ "dev:test:kaocha" ];
          checkCommand = "clojure -Srepro -M:dev:test:kaocha";
          gitRev = clj-helpers.lib.gitRev self;
          nativeBuildInputs = [
            pkgs.cfssl
            pkgs.pebble
          ];
        };
    in
    devenv.lib.mkFlake ./. {
      inherit inputs;
      withOverlays = [
        devshell.overlays.default
        devenv.overlays.default
      ];
      packages = {
        default = package;
        locker = pkgs: (package pkgs).locker;
      };
      checks = {
        tests = pkgs: self.packages.${pkgs.system}.default;
      };
      devShell =
        pkgs:
        pkgs.devshell.mkShell {
          imports = [
            devenv.capsules.base
            devenv.capsules.clojure
          ];
          commands = [
            { package = pkgs.cfssl; }
            { package = pkgs.pebble; }
          ];
          packages = [
            self.packages.${pkgs.system}.locker
            pkgs.jdk25
          ];
        };
    };
}
