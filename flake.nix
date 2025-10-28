{
  description = "dev env";
  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0.1"; # tracks nixpkgs unstable branch
    flakelight.url = "github:nix-community/flakelight";
    flakelight.inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs =
    {
      self,
      flakelight,
      ...
    }:
    flakelight ./. {

      devShell =
        pkgs:
        let
          javaVersion = "25";
          jdk = pkgs."jdk${javaVersion}";
          clojure = pkgs.clojure.override { inherit jdk; };
          libraries = [ ];
        in
        {
          packages = [
            clojure
            jdk
            pkgs.pebble
            pkgs.clojure-lsp
            pkgs.clj-kondo
            pkgs.cljfmt
            pkgs.babashka
            pkgs.git
            (pkgs.writeScriptBin "run-clojure-mcp" ''
              #!/usr/bin/env bash
                set -euo pipefail
                PORT_FILE=''${1:-.nrepl-port}
                PORT=''${1:-4888}
                if [ -f "$PORT_FILE" ]; then
                PORT=$(cat ''${PORT_FILE})
                fi
                ${clojure}/bin/clojure -X:mcp/clojure :port $PORT
            '')
          ];
          env.LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath libraries;
          shellHook = ''
            mkdir -p extra/
            pushd extra/
            test -f rfc8555.txt || wget -q https://www.rfc-editor.org/rfc/rfc8555.txt
            test -f rfc9773.txt || wget -q https://www.rfc-editor.org/rfc/rfc9773.txt
            popd
          '';
        };

      flakelight.builtinFormatters = false;
      formatters = pkgs: {
        "*.nix" = "${pkgs.nixfmt}/bin/nixfmt";
        "*.clj" = "${pkgs.cljfmt}/bin/cljfmt fix";
      };
    };
}
