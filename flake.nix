{
  description = "Cassini testnet";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-21.05";
    mach-nix.url = "github:DavHau/mach-nix/3.3.0";
    mach-nix.inputs.nixpkgs.follows = "nixpkgs";
    mach-nix.inputs.pypi-deps-db.follows = "pypi-deps-db";
    pypi-deps-db.url = "github:DavHau/pypi-deps-db";
    pypi-deps-db.inputs.mach-nix.follows = "mach-nix";
  };

  outputs = inputs@{ self, nixpkgs, mach-nix, ... }:
    let
      inherit (builtins) attrValues;
      inherit (nixpkgs.lib) concatStringsSep genAttrs;
      systems = [ "x86_64-darwin" "x86_64-linux" ];
      forAllSystems = f: genAttrs systems (system: f system);
      overlay = final: prev: { };
      nixpkgsFor = forAllSystems (
        system:
        import nixpkgs {
          inherit system;
          config = { allowUnfree = true; };
          overlays = [ overlay ];
        }
      );
    in
    {
      devShell = forAllSystems (
        system:
        let
          pkgs = nixpkgsFor.${system};
          mach-nix-utils = mach-nix.lib.${system};
          myPython = mach-nix-utils.mkPython {
            ignoreDataOutdated = true;
            requirements = concatStringsSep "\n" [
              (builtins.readFile ./requirements.txt)
              # "black"
            ];
            packagesExtra = with pkgs; [ ];
          };
        in
        pkgs.mkShell {
          PYTHONPATH = ".";
          nativeBuildInputs = with pkgs; [
            myPython
            python3Packages.black
          ];
          shellHook = ''
            set -oue pipefail
            PATH=bin:$PATH
          '';
        }
      );
    };
}
