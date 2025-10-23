# SPDX-FileCopyrightText: 2025 David James McCorrie <djmccorrie@gmail.com>
#
# SPDX-License-Identifier: Apache-2.0
{
  description = "Development environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
    nixpkgs-unstable.url = "github:nixos/nixpkgs/nixos-unstable";

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    nixpkgs,
    nixpkgs-unstable,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      pkgs-unstable = nixpkgs-unstable.legacyPackages.${system};
    in {
      devShells = {
        default = pkgs.mkShell {
          packages = [
            pkgs.python314
            pkgs.just
            pkgs.reuse
            pkgs-unstable.ruff
            pkgs.pyright
          ];
          env = {
          };
        };
      };

      formatter = nixpkgs.legacyPackages.${system}.alejandra;
    });
}
