{ pkgs, inputs, ... }:

let
  src = ../.;
  rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile "${src}/rust-toolchain.toml";
  crane-lib = (inputs.crane.mkLib pkgs).overrideToolchain rust-toolchain;
in
crane-lib.devShell {

    packages =
    with pkgs;
    [
        cargo-deny
        cargo-nextest
        # uv required for hegel property testing
        uv
    ]
    ++ lib.optionals stdenv.isLinux [ cargo-llvm-cov ];
}
