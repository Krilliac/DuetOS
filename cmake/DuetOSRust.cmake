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

find_package(Python3 3.11 REQUIRED COMPONENTS Interpreter)

set(DUETOS_RUST_TARGET "x86_64-unknown-none" CACHE STRING "Rust bare-metal target triple")
set(DUETOS_RUST_PROFILE "release" CACHE STRING "Rust profile used for the kernel Rust link unit")
set(DUETOS_RUST_BUILD_STD "core,alloc" CACHE STRING "Rust -Z build-std components")
set(DUETOS_RUST_BUILD_STD_FEATURES "compiler-builtins-mem" CACHE STRING "Rust -Z build-std-features")

function(duetos_collect_rust_workspace_depends)
    set(options)
    set(oneValueArgs AGGREGATE_MANIFEST CHECKER OUTPUT_VAR)
    set(multiValueArgs)
    cmake_parse_arguments(DUETOS_RUST_WORKSPACE "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    foreach(required_arg AGGREGATE_MANIFEST CHECKER OUTPUT_VAR)
        if(NOT DUETOS_RUST_WORKSPACE_${required_arg})
            message(FATAL_ERROR "duetos_collect_rust_workspace_depends missing required argument ${required_arg}")
        endif()
    endforeach()

    get_filename_component(aggregate_manifest
        "${DUETOS_RUST_WORKSPACE_AGGREGATE_MANIFEST}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
    get_filename_component(checker
        "${DUETOS_RUST_WORKSPACE_CHECKER}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
    get_filename_component(workspace_root "${CMAKE_SOURCE_DIR}" REALPATH)
    if(NOT EXISTS "${checker}")
        message(FATAL_ERROR "Rust workspace checker not found: ${checker}")
    endif()

    execute_process(
        COMMAND "${Python3_EXECUTABLE}" "${checker}"
                --repo-root "${workspace_root}"
                --aggregate-manifest "${aggregate_manifest}"
                --emit-cmake-deps
        RESULT_VARIABLE checker_result
        OUTPUT_VARIABLE checker_output
        ERROR_VARIABLE checker_error
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT checker_result EQUAL 0)
        string(STRIP "${checker_error}" checker_error)
        message(FATAL_ERROR
            "Rust workspace dependency derivation failed closed:\n${checker_error}")
    endif()

    string(REPLACE "\r" "" checker_output "${checker_output}")
    string(REPLACE "\n" ";" workspace_depends "${checker_output}")
    list(FILTER workspace_depends EXCLUDE REGEX "^$")
    if(NOT workspace_depends)
        message(FATAL_ERROR "Rust workspace checker returned no build dependencies")
    endif()

    # The checker supplies the authoritative current list.  CONFIGURE_DEPENDS
    # globs rooted only at the derived member manifests make additions/removals
    # trigger regeneration without duplicating the workspace list by hand.
    set(workspace_watch_patterns)
    foreach(dependency IN LISTS workspace_depends)
        if(dependency MATCHES "/Cargo\\.toml$")
            get_filename_component(member_dir "${dependency}" DIRECTORY)
            if(NOT member_dir STREQUAL "${workspace_root}")
                list(APPEND workspace_watch_patterns
                    "${member_dir}/*.rs"
                    "${member_dir}/*.h"
                    "${member_dir}/*.hh"
                    "${member_dir}/*.hpp"
                    "${member_dir}/*.hxx"
                    "${member_dir}/*.c"
                    "${member_dir}/*.cc"
                    "${member_dir}/*.cpp"
                    "${member_dir}/*.s"
                    "${member_dir}/*.S"
                    "${member_dir}/*.asm"
                    "${member_dir}/*.ld"
                    "${member_dir}/*.lds"
                    "${member_dir}/Cargo.toml"
                    "${member_dir}/.cargo/config"
                    "${member_dir}/.cargo/config.toml"
                )
            endif()
        endif()
    endforeach()
    if(NOT workspace_watch_patterns)
        message(FATAL_ERROR "Rust workspace checker returned no member manifests")
    endif()

    file(GLOB_RECURSE workspace_discovered_inputs CONFIGURE_DEPENDS
        LIST_DIRECTORIES false
        ${workspace_watch_patterns}
    )
    list(APPEND workspace_depends ${workspace_discovered_inputs} "${checker}")
    list(REMOVE_DUPLICATES workspace_depends)
    list(SORT workspace_depends)

    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${workspace_root}/Cargo.toml"
        "${aggregate_manifest}"
        "${checker}"
    )
    set(${DUETOS_RUST_WORKSPACE_OUTPUT_VAR} "${workspace_depends}" PARENT_SCOPE)
endfunction()

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
    if(DUETOS_RUST_PROFILE STREQUAL "release")
        set(profile_flag --release)
        set(profile_output_dir release)
    elseif(DUETOS_RUST_PROFILE STREQUAL "dev")
        set(profile_flag --profile dev)
        set(profile_output_dir debug)
    else()
        message(FATAL_ERROR
            "Unsupported DUETOS_RUST_PROFILE=${DUETOS_RUST_PROFILE}. "
            "Only release and dev have verified Cargo output-directory mappings.")
    endif()
    set(static_lib
        "${target_dir}/${DUETOS_RUST_TARGET}/${profile_output_dir}/lib${DUETOS_RUST_OUTPUT_NAME}.a")
    set(build_stamp
        "${target_dir}/${DUETOS_RUST_TARGET}/${profile_output_dir}/.${DUETOS_RUST_OUTPUT_NAME}.duetos-build.stamp")

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

    add_custom_command(
        OUTPUT "${build_stamp}"
        BYPRODUCTS "${static_lib}"
        COMMAND "${CMAKE_COMMAND}" -E env
                "CARGO_TARGET_DIR=${target_dir}"
                "${DUETOS_CARGO_EXE}" build
                ${profile_flag}
                --manifest-path "${manifest_path}"
                --locked
                --target ${DUETOS_RUST_TARGET}
                -Z build-std=${DUETOS_RUST_BUILD_STD}
                -Z build-std-features=${DUETOS_RUST_BUILD_STD_FEATURES}
        COMMAND "${CMAKE_COMMAND}" -E touch "${build_stamp}"
        DEPENDS ${rust_sources} ${workspace_deps} ${DUETOS_RUST_EXTRA_DEPENDS}
        WORKING_DIRECTORY "${crate_dir}"
        COMMENT "Building ${DUETOS_RUST_NAME} Rust crate (${DUETOS_RUST_PROFILE}, ${DUETOS_RUST_TARGET})"
        VERBATIM
    )

    add_custom_target(${DUETOS_RUST_NAME}-rust DEPENDS "${build_stamp}")

    set(include_dir "${DUETOS_RUST_INCLUDE_DIR}")
    if(include_dir AND NOT IS_ABSOLUTE "${include_dir}")
        get_filename_component(include_dir "${include_dir}" ABSOLUTE BASE_DIR "${crate_dir}")
    endif()

    set(${DUETOS_RUST_LIB_VAR} "${static_lib}" PARENT_SCOPE)
    set(${DUETOS_RUST_INCLUDE_VAR} "${include_dir}" PARENT_SCOPE)
    set(${DUETOS_RUST_TARGET_VAR} "${DUETOS_RUST_NAME}-rust" PARENT_SCOPE)
endfunction()
