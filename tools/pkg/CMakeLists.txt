# tools/pkg/CMakeLists.txt
#
# duet-pkg — DuetOS federated package manager.
#
# Standalone CMake project (NOT pulled from the root CMakeLists.txt
# because the kernel build pins the freestanding toolchain
# `cmake/toolchains/x86_64-kernel.cmake` which is hostile to a
# hosted binary that wants <filesystem>, <expected>, libcurl, and
# libsodium). Mirrors the `tests/host/` pattern: drop into the
# directory, configure, build, run.
#
# Build via:
#
#   cmake -S tools/pkg -B build/duet-pkg -DCMAKE_BUILD_TYPE=Release
#   cmake --build build/duet-pkg --parallel $(nproc)
#   ctest --test-dir build/duet-pkg --output-on-failure
#
# A future slice may add `option(DUETOS_BUILD_TOOLS ...)` to the
# root project that drives this directory via ExternalProject, so
# `cmake --build build/x86_64-debug --target duet-pkg` builds both
# the kernel and the package manager in one go. Not needed yet —
# the standalone path matches what every existing contributor
# does for host-side tooling.

cmake_minimum_required(VERSION 3.25)
project(duet-pkg
    LANGUAGES CXX
    DESCRIPTION "DuetOS federated package manager")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Mirror the discipline of the kernel + tests/host build: zero
# warnings, full pedantic mode, shadow + sign-conversion called
# out. `-fno-exceptions` + `-fno-rtti` — duet-pkg uses
# `std::expected<T, DuetPkgError>` for all fallible paths, like
# the kernel's `Result<T, E>`.
add_compile_options(
    -Wall -Wextra -Wpedantic -Werror
    -Wshadow -Wconversion -Wsign-conversion
    -fno-exceptions -fno-rtti
)

option(DUETOS_PKG_SANITIZERS "Enable ASan + UBSan for duet-pkg tests" ON)
if(DUETOS_PKG_SANITIZERS)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# ----------------------------------------------------------------------------
# Dependencies — pulled via FetchContent so a contributor on a
# bare clone gets everything they need from `cmake -S`.
#
# Phase 1 needs only toml++. libcurl + libsodium come in Phases
# 2 + 3.
# ----------------------------------------------------------------------------
include(FetchContent)

# toml++ — header-only TOML parser. Pin to a release tag so the
# build is reproducible. Exceptions are disabled at compile time
# (`TOML_EXCEPTIONS=0`) so parse failures return a
# `toml::parse_result` we can check rather than throwing.
FetchContent_Declare(tomlplusplus
    GIT_REPOSITORY https://github.com/marzer/tomlplusplus.git
    GIT_TAG        v3.4.0
    GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(tomlplusplus)

# libsodium — SHA-256 + Ed25519. The system package on every
# distro we care about (apt: libsodium-dev, brew: libsodium,
# pacman: libsodium) ships pkg-config metadata. FetchContent
# fall-back is deliberately omitted — libsodium's autotools
# build doesn't play well with FetchContent, and rolling our
# own crypto is forbidden per the spec.
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)

# libcurl — HTTP / HTTPS / Range support. Same pkg-config path;
# every distro packages it.
pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)

# ----------------------------------------------------------------------------
# Library: everything but main(), so tests can link the same code.
# ----------------------------------------------------------------------------
add_library(duet-pkg-lib STATIC
    src/error.cpp
    src/repo/repo_manifest.cpp
    src/repo/package_manifest.cpp
    src/repo/repo_manager.cpp
    src/registry/registry.cpp
    src/crypto/verifier.cpp
    src/crypto/keying.cpp
    src/net/fetcher.cpp
    src/resolve/resolver.cpp
    src/install/installer.cpp
    src/install/uninstaller.cpp
    src/cli/cli.cpp
)
target_include_directories(duet-pkg-lib PUBLIC src)
target_link_libraries(duet-pkg-lib
    PUBLIC tomlplusplus::tomlplusplus
    PRIVATE PkgConfig::SODIUM PkgConfig::CURL
)
target_compile_definitions(duet-pkg-lib PUBLIC TOML_EXCEPTIONS=0)

# ----------------------------------------------------------------------------
# Executable.
# ----------------------------------------------------------------------------
add_executable(duet-pkg src/main.cpp)
target_link_libraries(duet-pkg PRIVATE duet-pkg-lib)

# ----------------------------------------------------------------------------
# Tests.
# ----------------------------------------------------------------------------
enable_testing()
add_executable(test_manifest_parse tests/test_manifest_parse.cpp)
target_link_libraries(test_manifest_parse PRIVATE duet-pkg-lib)
target_compile_definitions(test_manifest_parse PRIVATE
    DUET_PKG_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")
add_test(NAME manifest_parse COMMAND test_manifest_parse)

add_executable(test_verifier tests/test_verifier.cpp)
target_link_libraries(test_verifier PRIVATE duet-pkg-lib PkgConfig::SODIUM)
target_compile_definitions(test_verifier PRIVATE
    DUET_PKG_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")
add_test(NAME verifier COMMAND test_verifier)

add_executable(test_fetcher tests/test_fetcher.cpp)
target_link_libraries(test_fetcher PRIVATE duet-pkg-lib)
add_test(NAME fetcher COMMAND test_fetcher)
set_tests_properties(fetcher PROPERTIES SKIP_RETURN_CODE 77)

add_executable(test_repo_manager tests/test_repo_manager.cpp)
target_link_libraries(test_repo_manager PRIVATE duet-pkg-lib PkgConfig::SODIUM)
add_test(NAME repo_manager COMMAND test_repo_manager)
set_tests_properties(repo_manager PROPERTIES SKIP_RETURN_CODE 77)

add_executable(test_resolver tests/test_resolver.cpp)
target_link_libraries(test_resolver PRIVATE duet-pkg-lib)
add_test(NAME resolver COMMAND test_resolver)

add_executable(test_installer tests/test_installer.cpp)
target_link_libraries(test_installer PRIVATE duet-pkg-lib PkgConfig::SODIUM)
add_test(NAME installer COMMAND test_installer)
set_tests_properties(installer PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 120)

message(STATUS "duet-pkg configured (C++${CMAKE_CXX_STANDARD}, sanitizers=${DUETOS_PKG_SANITIZERS})")
