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

        # The static verifier site, for self-hosting.
        verifier = pkgs.buildNpmPackage {
          pname = "receipts-verifier";
          version = "0.1.1";
          # The whole repo, not just verifier/: the shared rejection
          # corpus lives at testdata/rejections.json and both test suites
          # read it, so a derivation scoped to verifier/ would run the
          # verifier's tests with that gate quietly absent.
          src = ./.;
          # Descend after unpacking rather than naming a source root: the
          # unpacked directory is named after the store path, not "source".
          postUnpack = "sourceRoot=$sourceRoot/verifier";
          # The dependency fetch needs the directory holding
          # package-lock.json, which is verifier/, while the build needs
          # the whole repo (see src below). Naming them separately keeps
          # both true. Update the hash with:
          #   nix run nixpkgs#prefetch-npm-deps -- verifier/package-lock.json
          npmDeps = pkgs.fetchNpmDeps {
            src = ./verifier;
            hash = "sha256-taIAqDL0K95MHUiNkf06O3ip1CaKKR6fVsJcIms1SSk=";
          };
          # npm run build typechecks and bundles; it does not run vitest,
          # so without this `nix flake check` reported a green verifier
          # having never run a verifier test.
          doCheck = true;
          checkPhase = ''
            runHook preCheck
            npm test
            runHook postCheck
          '';
          installPhase = ''
            runHook preInstall
            cp -r dist $out
            runHook postInstall
          '';
        };

        # vendorHash is null: standard library only.
        goModule = pkgs.buildGoModule {
          pname = "receipts";
          version = "0.1.1";
          src = ./.;
          vendorHash = null;
          # The root package "." is listed on purpose: it holds the
          # shared rejection corpus and the interop gate, and leaving it
          # out meant this check was green without running either. The
          # interop test needs npm, which the sandbox has not got, so
          # that one skips here; CI runs it and asserts it did not skip.
          subPackages = [ "." "receipts" "c2pa" "provenance" "history" "claims" ];
        };
      in
      {
        packages = {
          inherit verifier;
          default = verifier;
        };

        checks = {
          inherit verifier;
          go = goModule;
          gofmt = pkgs.runCommand "gofmt-check" { nativeBuildInputs = [ pkgs.go ]; } ''
            cd ${./.}
            unformatted="$(gofmt -l . || true)"
            if [ -n "$unformatted" ]; then
              echo "these files are not gofmt-clean:"
              echo "$unformatted"
              exit 1
            fi
            touch $out
          '';
        };

        formatter = pkgs.nixpkgs-fmt;

        # Both toolchains: the interop test signs in Go and checks it with
        # the verifier's vitest suite.
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go
            nodejs_22
            git
            gitleaks
          ];
          shellHook = ''
            echo "receipts dev shell (go $(go version | cut -d\" \" -f3), node $(node --version))"
            echo "  go test ./..."
            echo "  cd verifier && npm install && npm test"
          '';
        };
      });
}
