# DuetOS Rust integration helpers.
#
# Rust subsystem crates are linked through a single aggregate static library.
# C++ owns subsystem orchestration and calls into Rust only through narrow C FFI;
# this helper standardizes the cargo invocation, target directory, dependency
# tracking, and CMake variables for that Rust link unit.

include_guard(GLOBAL)

find_program(DUETOS_CARGO_EXE cargo
    HINTS "$ENV{HOME}/.cargo/bin" /root/.cargo/bin /usr/local/cargo/bin
    DOC "Path to cargo (rustup-managed)")
if(NOT DUETOS_CARGO_EXE)
    message(FATAL_ERROR
        "cargo not found on PATH. DuetOS Rust crates require "
        "rustup with the channel pinned in rust-toolchain.toml. "
        "See wiki/reference/Roadmap.md \"Rust bring-up\".")
endif()

set(DUETOS_RUST_TARGET "x86_64-unknown-none" CACHE STRING "Rust bare-metal target triple")
set(DUETOS_RUST_PROFILE "release" CACHE STRING "Rust profile used for the kernel Rust link unit")
set(DUETOS_RUST_BUILD_STD "core,alloc" CACHE STRING "Rust -Z build-std components")
set(DUETOS_RUST_BUILD_STD_FEATURES "compiler-builtins-mem" CACHE STRING "Rust -Z build-std-features")

function(duetos_add_rust_staticlib)
    set(options)
    set(oneValueArgs NAME MANIFEST_PATH OUTPUT_NAME INCLUDE_DIR LIB_VAR INCLUDE_VAR TARGET_VAR)
    set(multiValueArgs EXTRA_DEPENDS)
    cmake_parse_arguments(DUETOS_RUST "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    foreach(required_arg NAME MANIFEST_PATH OUTPUT_NAME LIB_VAR INCLUDE_VAR TARGET_VAR)
        if(NOT DUETOS_RUST_${required_arg})
            message(FATAL_ERROR "duetos_add_rust_staticlib missing required argument ${required_arg}")
        endif()
    endforeach()

    get_filename_component(crate_dir "${DUETOS_RUST_MANIFEST_PATH}" DIRECTORY)
    if(NOT IS_ABSOLUTE "${crate_dir}")
        get_filename_component(crate_dir "${crate_dir}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
    endif()

    get_filename_component(manifest_path "${DUETOS_RUST_MANIFEST_PATH}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
    set(target_dir "${CMAKE_CURRENT_BINARY_DIR}/${DUETOS_RUST_NAME}-cargo-target")
    set(static_lib
        "${target_dir}/${DUETOS_RUST_TARGET}/${DUETOS_RUST_PROFILE}/lib${DUETOS_RUST_OUTPUT_NAME}.a")

    file(GLOB_RECURSE rust_sources CONFIGURE_DEPENDS
        "${crate_dir}/src/*.rs"
        "${crate_dir}/Cargo.toml"
        "${crate_dir}/.cargo/config.toml"
    )

    set(workspace_deps
        "${CMAKE_SOURCE_DIR}/Cargo.toml"
        "${CMAKE_SOURCE_DIR}/Cargo.lock"
        "${CMAKE_SOURCE_DIR}/.cargo/config.toml"
        "${CMAKE_SOURCE_DIR}/rust-toolchain.toml"
    )

    if(DUETOS_RUST_PROFILE STREQUAL "release")
        set(profile_flag --release)
    else()
        set(profile_flag --profile ${DUETOS_RUST_PROFILE})
    endif()

    add_custom_command(
        OUTPUT "${static_lib}"
        COMMAND "${CMAKE_COMMAND}" -E env
                "CARGO_TARGET_DIR=${target_dir}"
                "${DUETOS_CARGO_EXE}" build
                ${profile_flag}
                --manifest-path "${manifest_path}"
                --locked
                --target ${DUETOS_RUST_TARGET}
                -Z build-std=${DUETOS_RUST_BUILD_STD}
                -Z build-std-features=${DUETOS_RUST_BUILD_STD_FEATURES}
        DEPENDS ${rust_sources} ${workspace_deps} ${DUETOS_RUST_EXTRA_DEPENDS}
        WORKING_DIRECTORY "${crate_dir}"
        COMMENT "Building ${DUETOS_RUST_NAME} Rust crate (${DUETOS_RUST_PROFILE}, ${DUETOS_RUST_TARGET})"
        VERBATIM
    )

    add_custom_target(${DUETOS_RUST_NAME}-rust DEPENDS "${static_lib}")

    set(include_dir "${DUETOS_RUST_INCLUDE_DIR}")
    if(include_dir AND NOT IS_ABSOLUTE "${include_dir}")
        get_filename_component(include_dir "${include_dir}" ABSOLUTE BASE_DIR "${crate_dir}")
    endif()

    set(${DUETOS_RUST_LIB_VAR} "${static_lib}" PARENT_SCOPE)
    set(${DUETOS_RUST_INCLUDE_VAR} "${include_dir}" PARENT_SCOPE)
    set(${DUETOS_RUST_TARGET_VAR} "${DUETOS_RUST_NAME}-rust" PARENT_SCOPE)
endfunction()
