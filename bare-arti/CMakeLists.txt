# Builds the in-process Bare addon (the cdylib + bare-rust binding) via
# bare-make. The Tor core is plain Rust and is verified separately with cargo;
# this file only wires the `bare` feature into a loadable Bare addon.
#
# Requires the Bare toolchain (bare-make, cmake-bare, cmake-cargo) — see
# package.json "build:addon". Not exercised by the cargo-based verification.

cmake_minimum_required(VERSION 3.25)

find_package(cmake-bare REQUIRED PATHS node_modules/cmake-bare)
find_package(cmake-cargo REQUIRED PATHS node_modules/cmake-cargo)

project(bare_arti C)

bare_target(target)

# Build the crate's cdylib with the `bare` feature and wrap it as a Bare addon.
add_bare_addon(
  bare_arti
  TARGET ${target}
)

cargo_build(
  MANIFEST_PATH Cargo.toml
  FEATURES bare
  TARGET ${target}
)
