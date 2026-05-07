{
  description = "A flake for memfd-secret";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    # Tools
    blueprint = {
      url = "github:numtide/blueprint";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Programming
    ## Rust
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
    };
  };

  outputs =
    inputs:
    inputs.blueprint {
      inherit inputs;
      nixpkgs.overlays = [
        inputs.rust-overlay.overlays.default
      ];
      prefix = "nix/";
    };
}
