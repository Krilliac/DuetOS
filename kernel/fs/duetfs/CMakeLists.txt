# DuetFS — Rust crate leaf target.
#
# Drives `cargo build` for the kernel/fs/duetfs/ Rust crate and
# exposes the resulting `libduetfs.a` to the kernel link as a
# variable + a phony target. Two consumers (duetos-kernel-stage1 +
# duetos-kernel) link against it; both must `add_dependencies` on
# `duetfs-rust` so the cargo invocation runs before C++ link.
#
# Rules (Roadmap "Rust bring-up"):
#   - `cargo build --release --target x86_64-unknown-none`
#     -Z build-std=core,alloc with compiler-builtins-mem (so
#     memcpy / memset get pulled into the staticlib).
#   - panic = abort, lto = thin (set in Cargo.toml's [profile.release]).
#   - The toolchain channel + components are pinned in
#     ../../../rust-toolchain.toml; rustup picks them up
#     automatically when cargo runs in this directory.
#
# Build output:
#   ${DUETFS_TARGET_DIR}/x86_64-unknown-none/release/libduetfs.a
#
# A re-run of cargo only happens when one of the .rs files (or the
# Cargo.toml) changes; CMake's add_custom_command tracks DEPENDS.

find_program(DUETOS_CARGO_EXE cargo
    HINTS "$ENV{HOME}/.cargo/bin" /root/.cargo/bin /usr/local/cargo/bin
    DOC "Path to cargo (rustup-managed)")
if(NOT DUETOS_CARGO_EXE)
    message(FATAL_ERROR
        "cargo not found on PATH. The DuetFS Rust crate requires "
        "rustup with the channel pinned in rust-toolchain.toml. "
        "See wiki/reference/Roadmap.md \"Rust bring-up\".")
endif()

set(DUETFS_CRATE_DIR  "${CMAKE_CURRENT_SOURCE_DIR}")
set(DUETFS_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo-target")
set(DUETFS_RUST_TARGET "x86_64-unknown-none")
set(DUETFS_PROFILE_DIR "release")

# Keep this in lockstep with the crate's actual output name.
set(DUETFS_STATIC_LIB
    "${DUETFS_TARGET_DIR}/${DUETFS_RUST_TARGET}/${DUETFS_PROFILE_DIR}/libduetfs.a")

# Globbed source list — every .rs + the manifest. CONFIGURE_DEPENDS
# means adding a new .rs file in src/ re-runs CMake configure
# automatically without an edit here.
file(GLOB_RECURSE DUETFS_RUST_SOURCES CONFIGURE_DEPENDS
    "${DUETFS_CRATE_DIR}/src/*.rs"
    "${DUETFS_CRATE_DIR}/Cargo.toml"
    "${DUETFS_CRATE_DIR}/.cargo/config.toml"
    "${CMAKE_SOURCE_DIR}/rust-toolchain.toml"
)

add_custom_command(
    OUTPUT  "${DUETFS_STATIC_LIB}"
    COMMAND "${CMAKE_COMMAND}" -E env
            "CARGO_TARGET_DIR=${DUETFS_TARGET_DIR}"
            "${DUETOS_CARGO_EXE}" build
            --release
            --manifest-path "${DUETFS_CRATE_DIR}/Cargo.toml"
            --target ${DUETFS_RUST_TARGET}
            -Z build-std=core,alloc
            -Z build-std-features=compiler-builtins-mem
    DEPENDS ${DUETFS_RUST_SOURCES}
    WORKING_DIRECTORY "${DUETFS_CRATE_DIR}"
    COMMENT "Building duetfs Rust crate (release, ${DUETFS_RUST_TARGET})"
    VERBATIM
)

add_custom_target(duetfs-rust DEPENDS "${DUETFS_STATIC_LIB}")

# Promote to parent scope so kernel/CMakeLists.txt can wire both
# stage1 and stage2 against the same artifact.
set(DUETFS_STATIC_LIB    "${DUETFS_STATIC_LIB}"    PARENT_SCOPE)
set(DUETFS_INCLUDE_DIR   "${DUETFS_CRATE_DIR}/include" PARENT_SCOPE)
