# SPDX-FileCopyrightText: 2025 David James McCorrie <djmccorrie@gmail.com>
#
# SPDX-License-Identifier: Apache-2.0

{
  description = "Development environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
    nixpkgs-unstable.url = "github:nixos/nixpkgs/nixos-unstable";

    flake-utils.url = "github:numtide/flake-utils";

    pyproject-nix.url = "github:nix-community/pyproject.nix";
    pyproject-nix.inputs.nixpkgs.follows = "nixpkgs";

    uv2nix = {
      url = "github:pyproject-nix/uv2nix";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    pyproject-build-systems = {
      url = "github:pyproject-nix/build-system-pkgs";
      inputs.pyproject-nix.follows = "pyproject-nix";
      inputs.uv2nix.follows = "uv2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    nixpkgs-unstable,
    flake-utils,
    uv2nix,
    pyproject-nix,
    pyproject-build-systems,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      inherit (nixpkgs) lib;

      workspace = uv2nix.lib.workspace.loadWorkspace {workspaceRoot = ./.;};

      overlay = workspace.mkPyprojectOverlay {
        sourcePreference = "wheel"; # or sourcePreference = "sdist";
      };

      pyprojectOverrides = _final: _prev: {
        rcboat = _prev.rcboat.overrideAttrs (old: {
          passthru =
            old.passthru
            // {
              # Put all tests in the passthru.tests attribute set.
              # Nixpkgs also uses the passthru.tests mechanism for ofborg test discovery.
              #
              # For usage with Flakes we will refer to the passthru.tests attributes to construct the flake checks attribute set.
              tests = let
                # Construct a virtual environment with only the test dependency-group enabled for testing.
                virtualenv = _final.mkVirtualEnv "rcboat-pytest-env" {
                  rcboat = ["test"];
                };
              in
                (old.tests or {})
                // {
                  pytest = pkgs.stdenv.mkDerivation {
                    name = "${_final.rcboat.name}-pytest";
                    inherit (_final.rcboat) src;
                    nativeBuildInputs = [
                      virtualenv
                    ];
                    dontConfigure = true;

                    # Because this package is running tests, and not actually building the main package
                    # the build phase is running the tests.
                    #
                    # In this particular example we also output a HTML coverage report, which is used as the build output.
                    buildPhase = ''
                      runHook preBuild
                      pytest --cov-report html
                      runHook postBuild
                    '';

                    # Install the HTML coverage report into the build output.
                    #
                    # If you wanted to install multiple test output formats such as TAP outputs
                    # you could make this derivation a multiple-output derivation.
                    #
                    # See https://nixos.org/manual/nixpkgs/stable/#chap-multiple-output for more information on multiple outputs.
                    installPhase = ''
                      runHook preInstall
                      mv htmlcov $out
                      runHook postInstall
                    '';
                  };
                };
            };
        });
      };

      pkgs = nixpkgs.legacyPackages.${system};
      pkgs-unstable = nixpkgs-unstable.legacyPackages.${system};
      python = pkgs.python314;
      pythonSet =
        # Use base package set from pyproject.nix builders
        (pkgs.callPackage pyproject-nix.build.packages {
          inherit python;
        })
        .overrideScope
        (
          lib.composeManyExtensions [
            pyproject-build-systems.overlays.default
            overlay
            pyprojectOverrides
          ]
        );
    in {
      packages.default = pythonSet.mkVirtualEnv "rcboat-env" workspace.deps.default;

      # Make rcboat runnable with `nix run`
      apps = {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/rcboat";
        };
      };

      devShells = {
        default = pkgs.mkShell {
          packages = [
            python
            pkgs.uv
            pkgs.reuse
            pkgs-unstable.ruff
            pkgs.pyright
          ];
          env = {
            # Prevent uv from managing Python downloads
            UV_PYTHON_DOWNLOADS = "never";
            # Force uv to use nixpkgs Python interpreter
            UV_PYTHON = python.interpreter;
          };
          shellHook = ''
            unset PYTHONPATH
          '';
        };
      };

      checks = {inherit (pythonSet.rcboat.passthru.tests) pytest;};

      formatter = nixpkgs.legacyPackages.${system}.alejandra;
    });
}
