{
  description = "Receipts of Thought: format and client-side verifier for signed writing receipts";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        # The verifier is a static Vite + TypeScript site. The dev shell
        # gives you the Node toolchain to run its tests and build it.
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            nodejs_22
            git
          ];
          shellHook = ''
            echo "receipts dev shell (node $(node --version))"
            echo "  cd verifier && npm install && npm test"
          '';
        };
      });
}
