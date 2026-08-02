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
        # Two toolchains: Go for the trust-core module, Node for the
        # Vite + TypeScript verifier. The module's interop test signs a
        # bundle in Go and runs the verifier suite against it, so it
        # needs both.
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go
            nodejs_22
            git
          ];
          shellHook = ''
            echo "receipts dev shell (go $(go version | cut -d\" \" -f3), node $(node --version))"
            echo "  go test ./..."
            echo "  cd verifier && npm install && npm test"
          '';
        };
      });
}
