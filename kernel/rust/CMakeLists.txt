# DuetOS kernel Rust link unit.
#
# Cargo builds one staticlib containing every Rust subsystem rlib. Linking a
# single Rust-produced archive keeps core/alloc/compiler_builtins and the panic
# runtime unique in the final C++ kernel link.

include("${CMAKE_SOURCE_DIR}/cmake/DuetOSRust.cmake")

duetos_rust_sandbox_paths(
    duetos-kernel-rust
    DUETOS_RUST_CONTROLLED_HOME
    DUETOS_RUST_CONTROLLED_WORKING_DIRECTORY
)

duetos_collect_rust_workspace_depends(
    AGGREGATE_MANIFEST "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml"
    CHECKER "${CMAKE_SOURCE_DIR}/tools/test/check-rust-ffi.py"
    CARGO_HOME "${DUETOS_RUST_CONTROLLED_HOME}"
    CARGO_WORKING_DIRECTORY "${DUETOS_RUST_CONTROLLED_WORKING_DIRECTORY}"
    OUTPUT_VAR DUETOS_RUST_WORKSPACE_DEPENDS
)

# This target deliberately has no output stamp: it runs on every requested
# Rust/kernel build and fails before Cargo can consume a newly introduced,
# untracked source/configuration escape hatch.
add_custom_target(duetos-kernel-rust-ffi-check
    COMMAND "${CMAKE_COMMAND}" -E make_directory
            "${DUETOS_RUST_CONTROLLED_HOME}"
            "${DUETOS_RUST_CONTROLLED_WORKING_DIRECTORY}"
    COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_SOURCE_DIR}/tools/test/check-rust-ffi.py"
            --repo-root "${CMAKE_SOURCE_DIR}"
            --aggregate-manifest "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml"
            --cargo-working-directory "${DUETOS_RUST_CONTROLLED_WORKING_DIRECTORY}"
            --cargo-home "${DUETOS_RUST_CONTROLLED_HOME}"
    COMMENT "Validating the complete Rust/C FFI boundary"
    VERBATIM
)

duetos_add_rust_staticlib(
    NAME duetos-kernel-rust
    MANIFEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml"
    OUTPUT_NAME duetos_kernel_rust
    INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include"
    CARGO_HOME "${DUETOS_RUST_CONTROLLED_HOME}"
    CARGO_WORKING_DIRECTORY "${DUETOS_RUST_CONTROLLED_WORKING_DIRECTORY}"
    LIB_VAR DUETOS_KERNEL_RUST_STATIC_LIB
    INCLUDE_VAR DUETOS_KERNEL_RUST_INCLUDE_DIR
    TARGET_VAR DUETOS_KERNEL_RUST_TARGET
    EXTRA_DEPENDS
        ${DUETOS_RUST_WORKSPACE_DEPENDS}
)
add_dependencies(${DUETOS_KERNEL_RUST_TARGET} duetos-kernel-rust-ffi-check)

set(DUETOS_KERNEL_RUST_STATIC_LIB "${DUETOS_KERNEL_RUST_STATIC_LIB}" PARENT_SCOPE)
set(DUETOS_KERNEL_RUST_TARGET "${DUETOS_KERNEL_RUST_TARGET}" PARENT_SCOPE)
