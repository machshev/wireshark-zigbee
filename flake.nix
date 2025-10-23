# SPDX-FileCopyrightText: 2025 David James McCorrie <djmccorrie@gmail.com>
#
# SPDX-License-Identifier: Apache-2.0
{
  description = "Development environment";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
    nixpkgs-unstable.url = "github:nixos/nixpkgs/nixos-unstable";

    flake-utils.url = "github:numtide/flake-utils";

    rust-overlay = {
      url = "github:oxalica/rust-overlay/stable";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    nixpkgs,
    nixpkgs-unstable,
    flake-utils,
    rust-overlay,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {
        inherit system overlays;
      };
      pkgs-unstable = nixpkgs-unstable.legacyPackages.${system};
    in {
      devShells = {
        default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rust-bin.stable.latest.default
            cargo-nextest
            cargo-udeps
            cargo-vet
            cargo-about
            cargo-release

            rust-analyzer
            rustfmt

            adrs
            typos

            # If the dependencies need system libs, you usually need pkg-conf
            pkg-config
            openssl
            udev

            # Python dependencies for sonoff_zigbee_extcap.py
            python313
            python313Packages.pyserial-asyncio
            python313Packages.scapy
          ];
          packages = [
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
