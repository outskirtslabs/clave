{
  description = "dev env";
  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1"; # tracks nixpkgs unstable branch
    devshell.url = "github:numtide/devshell";
    devshell.inputs.nixpkgs.follows = "nixpkgs";
    devenv.url = "https://flakehub.com/f/ramblurr/nix-devenv/*";
    devenv.inputs.nixpkgs.follows = "nixpkgs";
    clj-nix.url = "github:jlesquembre/clj-nix";
    clj-nix.inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs =
    inputs@{
      self,
      clj-nix,
      devenv,
      devshell,
      ...
    }:
    devenv.lib.mkFlake ./. {
      inherit inputs;
      withOverlays = [
        devshell.overlays.default
        devenv.overlays.default
        clj-nix.overlays.default
      ];
      packages = {
        default =
          pkgs:
          let
            root = toString ./.;
            gitRev =
              if self ? rev then
                self.rev
              else if self ? dirtyRev then
                self.dirtyRev
              else
                "dirty";
            projectSrc = pkgs.lib.cleanSourceWith {
              src = ./.;
              filter =
                path: _type:
                let
                  rel = pkgs.lib.removePrefix (root + "/") (toString path);
                  base = builtins.baseNameOf path;
                in
                !(
                  base == ".git"
                  || rel == "result"
                  || pkgs.lib.hasPrefix "target/" rel
                );
            };
          in
          pkgs.mkCljLib {
            inherit projectSrc;
            name = "com.outskirtslabs/clave";
            version = "0.0.0";
            nativeBuildInputs = [
              pkgs.coreutils
            ];
            GIT_REV = gitRev;
            JAVA_HOME = pkgs.jdk25.home;
            buildCommand = ''
              export JAVA_HOME="${pkgs.jdk25.home}"
              export JAVA_CMD="${pkgs.jdk25}/bin/java"
              clojure -T:build jar
            '';
          };
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
            pkgs.deps-lock
            pkgs.jdk25
          ];

        };
    };
}
