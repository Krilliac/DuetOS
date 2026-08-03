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
set(DUETOS_RUST_TOOLCHAIN "nightly-2026-01-15")

function(duetos_rust_sandbox_paths name home_var work_var)
    if(DEFINED ENV{TMPDIR} AND NOT "$ENV{TMPDIR}" STREQUAL "")
        set(temp_root "$ENV{TMPDIR}")
    elseif(WIN32 AND DEFINED ENV{TEMP} AND NOT "$ENV{TEMP}" STREQUAL "")
        set(temp_root "$ENV{TEMP}")
    else()
        set(temp_root "/tmp")
    endif()
    get_filename_component(temp_root "${temp_root}" ABSOLUTE)
    string(SHA256 sandbox_hash "${CMAKE_BINARY_DIR}|${name}")
    string(SUBSTRING "${sandbox_hash}" 0 16 sandbox_suffix)
    set(sandbox_root "${temp_root}/duetos-cargo-${sandbox_suffix}")
    set(cargo_home "${sandbox_root}/home")
    set(cargo_work "${sandbox_root}/work")
    file(MAKE_DIRECTORY "${cargo_home}" "${cargo_work}")
    set(${home_var} "${cargo_home}" PARENT_SCOPE)
    set(${work_var} "${cargo_work}" PARENT_SCOPE)
endfunction()

function(duetos_collect_rust_workspace_depends)
    set(options)
    set(oneValueArgs AGGREGATE_MANIFEST CHECKER CARGO_HOME CARGO_WORKING_DIRECTORY OUTPUT_VAR)
    set(multiValueArgs)
    cmake_parse_arguments(DUETOS_RUST_WORKSPACE "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    foreach(required_arg AGGREGATE_MANIFEST CHECKER CARGO_HOME CARGO_WORKING_DIRECTORY OUTPUT_VAR)
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
                --cargo-working-directory "${DUETOS_RUST_WORKSPACE_CARGO_WORKING_DIRECTORY}"
                --cargo-home "${DUETOS_RUST_WORKSPACE_CARGO_HOME}"
                --emit-cmake-deps
        RESULT_VARIABLE checker_result
        OUTPUT_VARIABLE checker_output
        ERROR_VARIABLE checker_error
        OUTPUT_STRIP_TRAILING_WHITESPACE
        TIMEOUT 60
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

    # The bounded checker supplies the authoritative current dependency list.
    # Do not duplicate its traversal with an unbounded CMake GLOB_RECURSE.
    # The build-time audit target runs on every requested Rust/kernel build;
    # Cargo is restricted to --lib, so every newly compiled module must be
    # introduced through an already tracked source or manifest.
    list(APPEND workspace_depends "${checker}")
    list(REMOVE_DUPLICATES workspace_depends)
    list(SORT workspace_depends)

    get_filename_component(cargo_config_search_dir "${aggregate_manifest}" DIRECTORY)
    set(cargo_config_watch_paths)
    set(rustup_toolchain_watch_paths)
    while(TRUE)
        list(APPEND cargo_config_watch_paths
            "${cargo_config_search_dir}/.cargo/config"
            "${cargo_config_search_dir}/.cargo/config.toml"
        )
        list(APPEND rustup_toolchain_watch_paths
            "${cargo_config_search_dir}/rust-toolchain"
            "${cargo_config_search_dir}/rust-toolchain.toml"
        )
        if(cargo_config_search_dir STREQUAL workspace_root)
            break()
        endif()
        get_filename_component(cargo_config_parent "${cargo_config_search_dir}" DIRECTORY)
        if(cargo_config_parent STREQUAL cargo_config_search_dir)
            message(FATAL_ERROR "Rust aggregate manifest is outside the workspace root")
        endif()
        set(cargo_config_search_dir "${cargo_config_parent}")
    endwhile()

    # Content edits to an existing source must re-run dependency derivation.
    # That closes the add-include-now/edit-included-file-later stale-graph gap.
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${workspace_root}/Cargo.toml"
        "${aggregate_manifest}"
        "${checker}"
        ${workspace_depends}
        ${cargo_config_watch_paths}
        ${rustup_toolchain_watch_paths}
    )
    set(${DUETOS_RUST_WORKSPACE_OUTPUT_VAR} "${workspace_depends}" PARENT_SCOPE)
endfunction()

function(duetos_add_rust_staticlib)
    set(options)
    set(oneValueArgs NAME MANIFEST_PATH OUTPUT_NAME INCLUDE_DIR CARGO_HOME CARGO_WORKING_DIRECTORY LIB_VAR INCLUDE_VAR TARGET_VAR)
    set(multiValueArgs EXTRA_DEPENDS)
    cmake_parse_arguments(DUETOS_RUST "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    foreach(required_arg NAME MANIFEST_PATH OUTPUT_NAME CARGO_HOME CARGO_WORKING_DIRECTORY LIB_VAR INCLUDE_VAR TARGET_VAR)
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
    set(cargo_home "${DUETOS_RUST_CARGO_HOME}")
    set(cargo_working_directory "${DUETOS_RUST_CARGO_WORKING_DIRECTORY}")
    get_filename_component(cargo_sandbox_root "${cargo_home}" DIRECTORY)

    set(workspace_deps
        "${CMAKE_SOURCE_DIR}/Cargo.toml"
        "${CMAKE_SOURCE_DIR}/Cargo.lock"
        "${CMAKE_SOURCE_DIR}/.cargo/config.toml"
        "${CMAKE_SOURCE_DIR}/rust-toolchain.toml"
    )
    set(cargo_config_search_dir "${crate_dir}")
    while(TRUE)
        foreach(config_name config config.toml)
            set(config_candidate "${cargo_config_search_dir}/.cargo/${config_name}")
            if(EXISTS "${config_candidate}")
                list(APPEND workspace_deps "${config_candidate}")
            endif()
        endforeach()
        if(cargo_config_search_dir STREQUAL CMAKE_SOURCE_DIR)
            break()
        endif()
        get_filename_component(cargo_config_parent "${cargo_config_search_dir}" DIRECTORY)
        if(cargo_config_parent STREQUAL cargo_config_search_dir)
            message(FATAL_ERROR "Rust crate directory is outside the workspace root")
        endif()
        set(cargo_config_search_dir "${cargo_config_parent}")
    endwhile()
    list(REMOVE_DUPLICATES workspace_deps)

    add_custom_command(
        OUTPUT "${build_stamp}"
        BYPRODUCTS "${static_lib}"
        COMMAND "${CMAKE_COMMAND}" -E remove_directory "${cargo_sandbox_root}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${cargo_home}"
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${cargo_working_directory}"
        COMMAND "${CMAKE_COMMAND}" -E chdir "${cargo_working_directory}"
                "${CMAKE_COMMAND}" -E env
                --unset=RUSTC
                --unset=RUSTC_WRAPPER
                --unset=RUSTC_WORKSPACE_WRAPPER
                --unset=RUSTFLAGS
                --unset=CARGO_ENCODED_RUSTFLAGS
                --unset=CARGO_BUILD_RUSTC
                --unset=CARGO_BUILD_RUSTC_WRAPPER
                --unset=CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER
                --unset=CARGO_BUILD_RUSTFLAGS
                --unset=CARGO_TARGET_X86_64_UNKNOWN_NONE_LINKER
                --unset=CARGO_TARGET_X86_64_UNKNOWN_NONE_RUSTFLAGS
                "CARGO_HOME=${cargo_home}"
                "CARGO_TARGET_DIR=${target_dir}"
                "RUSTUP_TOOLCHAIN=${DUETOS_RUST_TOOLCHAIN}"
                "${DUETOS_CARGO_EXE}" build
                --lib
                ${profile_flag}
                --manifest-path "${manifest_path}"
                --locked
                --target ${DUETOS_RUST_TARGET}
                -Z build-std=${DUETOS_RUST_BUILD_STD}
                -Z build-std-features=${DUETOS_RUST_BUILD_STD_FEATURES}
        COMMAND "${CMAKE_COMMAND}" -E touch "${build_stamp}"
        DEPENDS "${manifest_path}" ${workspace_deps} ${DUETOS_RUST_EXTRA_DEPENDS}
        # Cleanup must run from a stable directory outside the sandbox it
        # removes.  Only the Cargo subprocess enters the recreated work dir.
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
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
