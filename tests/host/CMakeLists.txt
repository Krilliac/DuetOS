# tests/host/CMakeLists.txt
#
# Hosted unit tests for arch-agnostic kernel TUs. Builds with the
# host system compiler (clang/g++ from PATH), links against host
# glibc + libstdc++, and runs as ordinary Linux processes under
# CTest. Compared with the qemu-smoke matrix, these tests:
#
#   - run in milliseconds, not seconds
#   - can be parallelised across cores
#   - work under sanitizers (ASan, UBSan, TSan)
#   - assert directly on return values rather than grepping log
#     lines
#
# Scope today: trivially-pure kernel TUs whose behavior is fully
# determined by their inputs (no MMIO, no MSRs, no kernel state).
# As the kernel matures and more TUs grow `#ifdef DUETOS_HOST_TEST`
# shims around hardware accessors, the coverage here grows.
#
# Standalone project — NOT included from the root CMakeLists.txt.
# Build via (from the repo root):
#
#   cmake -S tests/host -B build/host-tests
#   cmake --build build/host-tests
#   ctest --test-dir build/host-tests --output-on-failure

cmake_minimum_required(VERSION 3.25)
project(duetos-host-tests C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Common warnings + treat-as-errors. Mirrors the kernel build's
# discipline so a host test that compiles cleanly at home compiles
# cleanly in CI.
if(MSVC)
    # The EXPECT_*/ASSERT_* helpers use the conventional `do { ... } while (0)`
    # single-statement wrapper. MSVC reports that intentional constant
    # condition as C4127 at /W4; suppress only that diagnostic and keep every
    # other warning fatal under /WX.
    add_compile_options(/W4 /WX /wd4127)
else()
    add_compile_options(
        -Wall -Wextra -Wpedantic -Werror
        -Wshadow -Wconversion -Wsign-conversion
    )
endif()

# Sanitizer toggles. CI runs one ASan+UBSan lane and one TSan lane. They are
# mutually exclusive because the runtimes cannot be composed reliably.
# Local developers can opt out of both for a faster compile.
option(DUETOS_HOST_TESTS_SANITIZERS "Enable ASan + UBSan for host unit tests" ON)
option(DUETOS_HOST_TESTS_TSAN "Enable ThreadSanitizer for host unit tests" OFF)
if(DUETOS_HOST_TESTS_SANITIZERS AND DUETOS_HOST_TESTS_TSAN)
    message(FATAL_ERROR "ASan+UBSan and TSan host-test modes are mutually exclusive")
endif()
if(MSVC AND DUETOS_HOST_TESTS_TSAN)
    message(FATAL_ERROR "DUETOS_HOST_TESTS_TSAN requires a compiler with -fsanitize=thread")
endif()
if(NOT MSVC)
    if(DUETOS_HOST_TESTS_SANITIZERS)
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    elseif(DUETOS_HOST_TESTS_TSAN)
        add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
        add_link_options(-fsanitize=thread)
    endif()
endif()

# Make the kernel headers reachable from host-test sources via the
# same include prefix the kernel uses (e.g. `#include "util/types.h"`).
# Only headers that are arch-neutral and dependency-light should
# actually be #included from a host test; pulling in something that
# transitively requires kernel-only globals would fail to link.
include_directories("${CMAKE_SOURCE_DIR}/../../kernel")

enable_testing()
find_package(Python3 3.11 REQUIRED COMPONENTS Interpreter)
find_package(Threads REQUIRED)
add_test(
    NAME rust_ffi_build_truth_self_test
    COMMAND Python3::Interpreter -B
            "${CMAKE_SOURCE_DIR}/../../tools/test/check-rust-ffi.py"
            --self-test
)

add_test(
    NAME rust_ffi_signature_fixtures
    COMMAND Python3::Interpreter -B
            "${CMAKE_SOURCE_DIR}/../../tools/test/test-rust-ffi-signatures.py"
)

add_test(
    NAME rust_ffi_boundary
    COMMAND Python3::Interpreter -B
            "${CMAKE_SOURCE_DIR}/../../tools/test/check-rust-ffi.py"
            --repo-root "${CMAKE_SOURCE_DIR}/../.."
)
set_tests_properties(
    rust_ffi_build_truth_self_test
    rust_ffi_signature_fixtures
    rust_ffi_boundary
    PROPERTIES TIMEOUT 90
)

add_test(
    NAME cxxeh_context_contract
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/../../tools/test/cxxeh-context-contract.py"
)

add_test(
    NAME verify_pe_exports
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/../../tools/build/test_verify_pe_exports.py"
)

add_test(
    NAME gen_fix_patches_retirement
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_SOURCE_DIR}/../../tools/build/test_gen_fix_patches.py"
)

add_test(
    NAME capability_access_static
    COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/../../tools/test/capability-access-static.py"
            --root "${CMAKE_SOURCE_DIR}/../.."
)

# A tracked TU that includes an untracked header compiles for the
# session that wrote both and for nobody else. Targeted-path staging
# (CLAUDE_PARALLEL.md forbids `git add -A`) is exactly how a new
# header gets left behind, so gate it here rather than in CI-only.
add_test(
    NAME include_tracked
    COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/../../tools/test/include-tracked-audit.py"
            --root "${CMAKE_SOURCE_DIR}/../.."
)

add_test(
    NAME iphlpapi_socket_abi
    COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/../../tools/test/iphlpapi-socket-abi.py"
            --root "${CMAKE_SOURCE_DIR}/../.."
)

add_test(
    NAME win32_syscall_numbers
    COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/../../tools/test/check-syscall-numbers.py"
            --root "${CMAKE_SOURCE_DIR}/../.."
)

add_test(
    NAME dll_def_exports
    COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/../../tools/test/check-dll-def-exports.py"
            --root "${CMAKE_SOURCE_DIR}/../.."
)

# The VMM's own vmm-tests target only builds on a WHP-capable
# Windows host; this models the same GDB packet length rules in
# Python so the untrusted-socket contract is checked everywhere.
add_test(
    NAME vmm_gdb_packet_vectors
    COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/../../tools/test/vmm-gdb-packet-vectors.py"
)

add_test(
    NAME kernel32_32_exports_complete
    COMMAND Python3::Interpreter
            "${CMAKE_SOURCE_DIR}/../../tools/test/check-dll-def-exports.py"
            --root "${CMAKE_SOURCE_DIR}/../.."
            --lib kernel32_32
            --warn-unexported
            --strict
)

# ---------------------------------------------------------------
# Test helper. Header-only single-file ASSERT framework — far
# lighter than gtest/Catch2, which would be the wrong dep for a
# fledgling host-test path. A failed ASSERT prints file:line +
# message and returns non-zero from main; CTest treats that as a
# test failure.
# ---------------------------------------------------------------

add_library(host_test_helper INTERFACE)
target_include_directories(host_test_helper INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")

# ---------------------------------------------------------------
# Individual test executables. Each test_*.cpp links against
# host_test_helper + (where applicable) the kernel TU under test.
#
# Adding a new test:
#   1. Drop test_<thing>.cpp into this directory.
#   2. Append `add_host_test(<thing>)` below.
#   3. Cite the kernel TU it covers in the .cpp's top-of-file
#      comment so the cross-reference is greppable.
# ---------------------------------------------------------------

function(add_host_test name)
    add_executable(test_${name} test_${name}.cpp)
    target_link_libraries(test_${name} PRIVATE host_test_helper)
    add_test(NAME ${name} COMMAND test_${name})
endfunction()

add_host_test(result)
add_host_test(syscall_error)
target_sources(test_syscall_error PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/syscall/error.cpp")
add_host_test(message_abi)
target_sources(test_message_abi PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/ipc/message_abi.cpp")
add_host_test(versioned_payload)
target_sources(test_versioned_payload PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/ipc/versioned_payload.cpp")
add_host_test(message_ring)
target_compile_definitions(test_message_ring PRIVATE DUETOS_HOST_TEST=1)
target_sources(
    test_message_ring
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/message_ring.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/message_abi.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/versioned_payload.cpp"
)
target_link_libraries(test_message_ring PRIVATE Threads::Threads)
add_host_test(load_plan)
target_sources(test_load_plan PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/loader/load_plan.cpp")
add_host_test(load_image)
target_sources(
    test_load_image
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/load_image.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/load_plan.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/crypto/sha256.cpp"
)
add_host_test(elf_load_image)
target_sources(
    test_elf_load_image
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/elf_load_image.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/load_image.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/load_plan.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/crypto/sha256.cpp"
)
add_host_test(exec_admission)
target_compile_definitions(test_exec_admission PRIVATE DUETOS_HOST_TEST=1)
target_sources(
    test_exec_admission
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/exec_admission.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/load_plan.cpp"
)
target_link_libraries(test_exec_admission PRIVATE Threads::Threads)
add_host_test(execd_protocol)
target_sources(
    test_execd_protocol
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/execd_protocol.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/message_abi.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/versioned_payload.cpp"
)
add_host_test(resource_domain)
target_link_libraries(test_resource_domain PRIVATE Threads::Threads)
add_host_test(resource_domain_channel)
target_link_libraries(test_resource_domain_channel PRIVATE Threads::Threads)
add_host_test(authorization_context)
target_link_libraries(test_authorization_context PRIVATE Threads::Threads)
add_host_test(credentials)
target_link_libraries(test_credentials PRIVATE Threads::Threads)
add_host_test(thread_group)
target_link_libraries(test_thread_group PRIVATE Threads::Threads)
add_host_test(gui_message_queue)
target_link_libraries(test_gui_message_queue PRIVATE Threads::Threads)
add_host_test(gui_message_policy)
target_sources(
    test_gui_message_policy
    PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/drivers/video/gui_message_policy.cpp"
)
target_link_libraries(test_gui_message_policy PRIVATE Threads::Threads)
add_host_test(gui_send_transaction)
target_link_libraries(test_gui_send_transaction PRIVATE Threads::Threads)
add_host_test(gui_send_service)
target_link_libraries(test_gui_send_service PRIVATE Threads::Threads)
add_host_test(kmessage_port)
target_compile_definitions(test_kmessage_port PRIVATE DUETOS_HOST_TEST=1)
target_sources(
    test_kmessage_port
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/kmessage_port.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/message_ring.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/message_abi.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/versioned_payload.cpp"
)
target_link_libraries(test_kmessage_port PRIVATE Threads::Threads)
add_host_test(object_transfer)
target_compile_definitions(test_object_transfer PRIVATE DUETOS_HOST_TEST=1)
target_sources(test_object_transfer PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/ipc/object_transfer.cpp")
target_link_libraries(test_object_transfer PRIVATE Threads::Threads)
add_host_test(endpoint_request_ledger)
target_sources(
    test_endpoint_request_ledger
    PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/ipc/endpoint_request_ledger.cpp"
)
target_link_libraries(test_endpoint_request_ledger PRIVATE Threads::Threads)
add_host_test(channel_core)
target_compile_definitions(test_channel_core PRIVATE DUETOS_HOST_TEST=1)
target_sources(
    test_channel_core
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/channel_core.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/endpoint_request_ledger.cpp"
)
target_link_libraries(test_channel_core PRIVATE Threads::Threads)
add_host_test(service_endpoint)
target_compile_definitions(test_service_endpoint PRIVATE DUETOS_HOST_TEST=1)
target_sources(
    test_service_endpoint
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_endpoint.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/channel_core.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/endpoint_request_ledger.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/proc/credentials.cpp"
)
target_link_libraries(test_service_endpoint PRIVATE Threads::Threads)
add_host_test(service_directory)
target_compile_definitions(test_service_directory PRIVATE DUETOS_HOST_TEST=1)
target_sources(
    test_service_directory
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_directory.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_endpoint.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/channel_core.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/endpoint_request_ledger.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/handle_table.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/proc/credentials.cpp"
)
target_link_libraries(test_service_directory PRIVATE Threads::Threads)
add_host_test(service_process_endpoint_teardown)
target_compile_definitions(test_service_process_endpoint_teardown PRIVATE DUETOS_HOST_TEST=1)
target_sources(
    test_service_process_endpoint_teardown
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_directory.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_endpoint.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/channel_core.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/endpoint_request_ledger.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/handle_table.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/proc/credentials.cpp"
)
target_link_libraries(test_service_process_endpoint_teardown PRIVATE Threads::Threads)
add_host_test(service_protocol_policy)
target_compile_definitions(test_service_protocol_policy PRIVATE DUETOS_HOST_TEST=1)
target_sources(
    test_service_protocol_policy
    PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/core/service_protocol_policy.cpp"
)
target_link_libraries(test_service_protocol_policy PRIVATE Threads::Threads)
add_host_test(service_endpoint_ingress)
target_compile_definitions(test_service_endpoint_ingress PRIVATE DUETOS_HOST_TEST=1)
target_sources(
    test_service_endpoint_ingress
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/syscall/service_endpoint_ingress.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_protocol_policy.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_endpoint.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/channel_core.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/endpoint_request_ledger.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/kmessage_port.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/message_ring.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/message_abi.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/versioned_payload.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/object_transfer.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/handle_table.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/proc/credentials.cpp"
)
target_link_libraries(test_service_endpoint_ingress PRIVATE Threads::Threads)
add_host_test(service_transition)
target_sources(test_service_transition PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/core/service_transition.cpp")
target_link_libraries(test_service_transition PRIVATE Threads::Threads)
add_host_test(service_manifest)
target_sources(
    test_service_manifest
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_manifest.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/crypto/sha256.cpp"
)
if(MSVC)
    # This hostile fixture intentionally keeps several maximum-size manifest
    # documents and plans alive in one test function. Match the 8 MiB stack
    # available on the Linux host-test lane instead of tripping Windows' 1 MiB
    # default before main can exercise the parser.
    target_link_options(test_service_manifest PRIVATE "/STACK:8388608")
endif()
add_host_test(service_object_package)
target_compile_definitions(test_service_object_package PRIVATE DUETOS_HOST_TEST=1)
target_sources(
    test_service_object_package
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_object_package.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_manifest.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_lifecycle_broker.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_transition.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/crypto/sha256.cpp"
)
target_link_libraries(test_service_object_package PRIVATE Threads::Threads)
if(MSVC)
    target_link_options(test_service_object_package PRIVATE "/STACK:8388608")
endif()
add_host_test(service_bootstrap_stage)
target_compile_definitions(test_service_bootstrap_stage PRIVATE DUETOS_HOST_TEST=1)
target_sources(
    test_service_bootstrap_stage
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_bootstrap_stage.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_object_package.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_manifest.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/elf_load_image.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/load_image.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/load_plan.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/exec_admission.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/crypto/sha256.cpp"
)
if(MSVC)
    target_link_options(test_service_bootstrap_stage PRIVATE "/STACK:8388608")
endif()
add_host_test(service_bootstrap_activation)
target_compile_definitions(test_service_bootstrap_activation PRIVATE DUETOS_HOST_TEST=1)
target_sources(
    test_service_bootstrap_activation
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_bootstrap_activation.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_bootstrap_stage.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_object_package.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_manifest.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_lifecycle_broker.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_exit_observer.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_runtime.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_directory.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_endpoint.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_transition.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/channel_core.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/endpoint_request_ledger.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/handle_table.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/proc/credentials.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/proc/resource_domain.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/elf_load_image.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/load_image.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/load_plan.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/loader/exec_admission.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/crypto/sha256.cpp"
)
if(MSVC)
    target_link_options(test_service_bootstrap_activation PRIVATE "/STACK:8388608")
endif()
add_host_test(service_lifecycle_broker)
target_compile_definitions(test_service_lifecycle_broker PRIVATE DUETOS_HOST_TEST=1)
target_sources(
    test_service_lifecycle_broker
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_lifecycle_broker.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_manifest.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_transition.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/crypto/sha256.cpp"
)
target_link_libraries(test_service_lifecycle_broker PRIVATE Threads::Threads)
add_host_test(service_publication_directory)
target_compile_definitions(test_service_publication_directory PRIVATE DUETOS_HOST_TEST=1)
target_sources(
    test_service_publication_directory
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_directory.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_lifecycle_broker.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_endpoint.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_protocol_policy.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_manifest.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_transition.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/channel_core.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/message_ring.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/message_abi.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/versioned_payload.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/endpoint_request_ledger.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/handle_table.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/proc/resource_domain.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/proc/credentials.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/crypto/sha256.cpp"
)
target_link_libraries(test_service_publication_directory PRIVATE Threads::Threads)
if(MSVC)
    target_link_options(test_service_publication_directory PRIVATE "/STACK:8388608")
endif()
add_host_test(service_exit_observer)
target_compile_definitions(test_service_exit_observer PRIVATE DUETOS_HOST_TEST=1)
target_sources(
    test_service_exit_observer
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/core/service_exit_observer.cpp"
)
target_link_libraries(test_service_exit_observer PRIVATE Threads::Threads)
add_host_test(serviced_protocol)
target_sources(
    test_serviced_protocol
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/core/serviced_protocol.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/message_abi.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/versioned_payload.cpp"
)

# User-mode serviced policy core: fixed-capacity manifest ownership, exact
# instance reconciliation, ordered lifecycle ACKs, restart budgets, dependency
# gating, and bounded command deduplication. Keep the implementation in the C
# language so this target is also an integration gate for the freestanding API.
set(SERVICED_SUPERVISOR_SOURCES
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/serviced/supervisor.c"
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/serviced/supervisor_policy.c"
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/serviced/supervisor_reconcile.c"
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/serviced/supervisor_event.c"
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/serviced/supervisor_command.c"
)
add_host_test(serviced_supervisor)
target_sources(test_serviced_supervisor PRIVATE ${SERVICED_SUPERVISOR_SOURCES})
target_include_directories(
    test_serviced_supervisor PRIVATE "${CMAKE_SOURCE_DIR}/../../userland/native-apps/serviced"
)

# Native service policy engines. These fixed-capacity C cores are kept
# independent of their still-dormant process entrypoints so hostile hosted
# tests can pin identity, cancellation, reply publication, and drain behavior.
set(REGISTRYD_STORE_SOURCES
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/registryd/registry_store.c"
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/registryd/registry_persistence.c"
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/registryd/registry_validate.c"
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/registryd/registry_recovery.c"
)
add_host_test(registryd_store)
target_sources(test_registryd_store PRIVATE ${REGISTRYD_STORE_SOURCES})
target_include_directories(
    test_registryd_store PRIVATE "${CMAKE_SOURCE_DIR}/../../userland/native-apps/registryd"
)

set(EXECD_WORKER_SOURCES
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/execd/worker.c"
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/execd/worker_request.c"
)
add_host_test(execd_worker)
target_sources(test_execd_worker PRIVATE ${EXECD_WORKER_SOURCES})
target_include_directories(
    test_execd_worker PRIVATE "${CMAKE_SOURCE_DIR}/../../userland/native-apps/execd"
)

set(DISPLAYD_ENGINE_SOURCES
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/displayd/display_engine.c"
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/displayd/display_engine_request.c"
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/displayd/display_engine_validate.c"
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/displayd/display_engine_event.c"
)
add_host_test(displayd_engine)
target_sources(test_displayd_engine PRIVATE ${DISPLAYD_ENGINE_SOURCES})
target_include_directories(
    test_displayd_engine PRIVATE "${CMAKE_SOURCE_DIR}/../../userland/native-apps/displayd"
)

set(NETD_SOCKET_ENGINE_SOURCES
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/netd/socket_engine.c"
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/netd/socket_engine_request.c"
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/netd/socket_engine_validate.c"
    "${CMAKE_SOURCE_DIR}/../../userland/native-apps/netd/socket_engine_lifecycle.c"
)
add_host_test(netd_socket_engine)
target_sources(test_netd_socket_engine PRIVATE ${NETD_SOCKET_ENGINE_SOURCES})
target_include_directories(
    test_netd_socket_engine PRIVATE "${CMAKE_SOURCE_DIR}/../../userland/native-apps/netd"
)

# Pure driver classification and exact-generation worker-lifetime contracts.
# They deliberately perform no host MMIO; the threaded lease fixture models
# hostile first-schedule-after-retire and concurrent publication races.
add_host_test(nic_ids)
add_host_test(wireless_watch)
target_link_libraries(test_wireless_watch PRIVATE Threads::Threads)
add_host_test(pcnet_restart)
target_link_libraries(test_pcnet_restart PRIVATE Threads::Threads)
add_host_test(virtio_net_restart)
target_link_libraries(test_virtio_net_restart PRIVATE Threads::Threads)

# Exact, effect-free MT7921 preflight validation for the first real-hardware
# target, plus hostile arithmetic coverage for PCI BAR probe responses.
add_host_test(mt7921_contract)
target_sources(
    test_mt7921_contract
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/drivers/net/mt7921_contract.cpp"
)
add_host_test(pci_bar_probe)
add_host_test(pci_endpoint_identity)

# The restart fixture exercises the real stack and TCP TUs, including their
# safe-Rust packet-parser ingress.  Build the no_std parser as an rlib and wrap
# it in the same panic=abort staticlib used by the network fuzzer; a C++ parser
# stand-in here would let the hosted test drift from the production FFI wall.
# These production networking TUs also use GCC/Clang freestanding builtins and
# GNU inline assembly through shared kernel headers, so this whole-source test
# is intentionally registered only on the Unix/Clang host lane.  The portable
# contract-only driver tests above continue to run under MSVC.
if(NOT MSVC)
find_program(DUETOS_HOST_RUSTC_EXECUTABLE rustc REQUIRED)
set(DUETOS_HOST_RUST_DIR "${CMAKE_CURRENT_BINARY_DIR}/host-rust")
set(DUETOS_NET_PARSERS_RLIB
    "${DUETOS_HOST_RUST_DIR}/libduetos_net_parsers.rlib"
)
set(DUETOS_NET_PARSERS_HOST_STATICLIB
    "${DUETOS_HOST_RUST_DIR}/duetos_net_parsers_host${CMAKE_STATIC_LIBRARY_SUFFIX}"
)
set(DUETOS_NET_PARSERS_SOURCE
    "${CMAKE_SOURCE_DIR}/../../kernel/net/parsers_rust/src/lib.rs"
)
set(DUETOS_NET_PARSERS_HOST_SHIM
    "${CMAKE_SOURCE_DIR}/../fuzz/host_shim/net_parsers_fuzz_shim.rs"
)

add_custom_command(
    OUTPUT "${DUETOS_NET_PARSERS_RLIB}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${DUETOS_HOST_RUST_DIR}"
    COMMAND "${DUETOS_HOST_RUSTC_EXECUTABLE}"
            --edition=2021
            -C panic=abort
            --crate-type=rlib
            --crate-name duetos_net_parsers
            -O
            "${DUETOS_NET_PARSERS_SOURCE}"
            -o "${DUETOS_NET_PARSERS_RLIB}"
    DEPENDS "${DUETOS_NET_PARSERS_SOURCE}"
    COMMENT "Building hosted duetos_net_parsers rlib"
    VERBATIM
)
add_custom_command(
    OUTPUT "${DUETOS_NET_PARSERS_HOST_STATICLIB}"
    COMMAND "${DUETOS_HOST_RUSTC_EXECUTABLE}"
            --edition=2021
            -C panic=abort
            --crate-type=staticlib
            --extern "duetos_net_parsers=${DUETOS_NET_PARSERS_RLIB}"
            "${DUETOS_NET_PARSERS_HOST_SHIM}"
            -o "${DUETOS_NET_PARSERS_HOST_STATICLIB}"
    DEPENDS
        "${DUETOS_NET_PARSERS_HOST_SHIM}"
        "${DUETOS_NET_PARSERS_RLIB}"
    COMMENT "Building hosted duetos_net_parsers static library"
    VERBATIM
)
add_custom_target(
    duetos_net_parsers_host_rust
    DEPENDS "${DUETOS_NET_PARSERS_HOST_STATICLIB}"
)

add_host_test(net_stack_restart)
target_compile_definitions(test_net_stack_restart PRIVATE DUETOS_HOST_TEST=1)
target_compile_options(
    test_net_stack_restart
    PRIVATE
        -Wno-conversion
        -Wno-sign-conversion
        -Wno-unused-variable
        -Wno-unused-parameter
)
target_include_directories(
    test_net_stack_restart
    BEFORE
    PRIVATE "${CMAKE_SOURCE_DIR}/../fuzz/host_shim"
)
target_include_directories(
    test_net_stack_restart
    PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/net/parsers_rust/include"
)
target_sources(
    test_net_stack_restart
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/net/stack.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/firewall.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/socket.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/tcp.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/tcp_segment.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/tcp_timer.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/tcp_cubic.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/tcp_sack.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/ipv6.cpp"
        "${CMAKE_SOURCE_DIR}/../fuzz/host_shim/net_stubs.cpp"
        "${CMAKE_SOURCE_DIR}/../fuzz/host_shim/fs_stubs.cpp"
)
add_dependencies(test_net_stack_restart duetos_net_parsers_host_rust)
target_link_libraries(
    test_net_stack_restart
    PRIVATE
        Threads::Threads
        "${DUETOS_NET_PARSERS_HOST_STATICLIB}"
)
set_property(
    TARGET test_net_stack_restart
    APPEND PROPERTY LINK_DEPENDS "${DUETOS_NET_PARSERS_HOST_STATICLIB}"
)

add_host_test(net_protocol_state_smp)
target_compile_definitions(test_net_protocol_state_smp PRIVATE DUETOS_HOST_TEST=1)
target_compile_options(
    test_net_protocol_state_smp
    PRIVATE
        -Wno-conversion
        -Wno-sign-conversion
        -Wno-unused-variable
        -Wno-unused-parameter
)
target_include_directories(
    test_net_protocol_state_smp
    BEFORE
    PRIVATE "${CMAKE_SOURCE_DIR}/../fuzz/host_shim"
)
target_include_directories(
    test_net_protocol_state_smp
    PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/net/parsers_rust/include"
)
target_sources(
    test_net_protocol_state_smp
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/net/stack.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/firewall.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/socket.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/tcp.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/tcp_segment.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/tcp_timer.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/tcp_cubic.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/tcp_sack.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/net/ipv6.cpp"
        "${CMAKE_SOURCE_DIR}/../fuzz/host_shim/net_stubs.cpp"
        "${CMAKE_SOURCE_DIR}/../fuzz/host_shim/fs_stubs.cpp"
)
add_dependencies(test_net_protocol_state_smp duetos_net_parsers_host_rust)
target_link_libraries(
    test_net_protocol_state_smp
    PRIVATE
        Threads::Threads
        "${DUETOS_NET_PARSERS_HOST_STATICLIB}"
)
set_property(
    TARGET test_net_protocol_state_smp
    APPEND PROPERTY LINK_DEPENDS "${DUETOS_NET_PARSERS_HOST_STATICLIB}"
)
endif()

add_host_test(gui_broker_protocol)
target_sources(
    test_gui_broker_protocol
    PRIVATE
        "${CMAKE_SOURCE_DIR}/../../kernel/drivers/video/gui_broker_protocol.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/drivers/video/gui_message_policy.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/message_abi.cpp"
        "${CMAKE_SOURCE_DIR}/../../kernel/ipc/versioned_payload.cpp"
)
# Phase A dynamic fix-discovery: decision logic is a freestanding header
# (syscall/inferred_gap_decide.h), so the test needs no kernel TU.
add_host_test(inferred_gap)
# HPET tick->ns scaling is a freestanding header (time/hpet_scale.h),
# so this needs no kernel TU. Pins the u64-overflow-at-5.12h fix.
add_host_test(hpet_scale)
add_host_test(thunk_retirement_policy)
add_host_test(pe_unwind_bounds)
# Demand-grown ring-3 stacks: the reservation planner and the #PF
# classifier are both freestanding (proc/user_stack.h), so the decision
# that gates committing memory for an untrusted PE is pinned here
# rather than only observed in a boot log.
add_host_test(user_stack)
# Phase B dynamic fix-discovery: config-proposal decision is freestanding
# (env/config_proposal_decide.h), no kernel TU.
add_host_test(config_proposal)
add_host_test(string)
add_host_test(cvt)
add_host_test(text_hash)
add_host_test(d3dcompiler)
# GDI region geometry: freestanding header (userland/libs/gdi32/gdi32_region.h),
# included by relative path — no extra target_sources needed.
add_host_test(gdi32_region)
# Off-screen GDI surface arithmetic: freestanding header
# (kernel/subsystems/win32/gdi_surface_math.h). Pins the guest-controlled
# allocation math (32-bit pixel-count wrap, DIB DWORD row padding,
# INT32_MIN biHeight) and the two-surface blit clip.
add_host_test(gdi_surface)
# i386 kernel32 companion path / seek-resolution core: freestanding
# header (userland/libs/kernel32_32/kernel32_32_paths.h), no kernel TU.
add_host_test(kernel32_32_paths)
# i386 kernel32 companion QueryPerformanceCounter epoch extension:
# freestanding header (kernel32_32_qpc.h). The 32-bit syscall return
# path truncates SYS_NOW_NS, so the wrap fixup is load-bearing.
add_host_test(kernel32_32_time)
# i386 kernel32 companion code-page / collation core: freestanding
# header (kernel32_32_nls.h), no kernel TU.
add_host_test(kernel32_32_nls)
# SMBIOS Type 17 (Memory Device) field decode: freestanding header
# (kernel/arch/x86_64/smbios_decode.h), no kernel TU. Covers the Size
# encoding's KB-vs-MB unit bit and Extended-Size escape, which a boot on
# any single machine only exercises one branch of.
add_host_test(smbios_type17)
# Telemetry percentage math: freestanding header
# (kernel/diag/telemetry_math.h), no kernel TU. Pins the summed-delta
# aggregate against the mean-of-percentages formula they get confused
# with, plus the torn-read clamps.
add_host_test(telemetry_cpu)
# CPU sensor decode: freestanding header
# (kernel/arch/x86_64/cpu_sensor_math.h), no kernel TU. The reads
# themselves are unverifiable off the target (QEMU models neither the
# AMD SMN aperture nor the Zen P-state MSRs), so the decode half is
# pinned here against synthetic register values instead.
add_host_test(cpu_sensor_math)
# Security-exception identity + boot-token parsing: freestanding header
# (kernel/security/exception_id.h), no kernel TU. This decides WHICH
# image an operator vouched for, so the lenient-direction failures
# (short digest accepted, key prefix mis-matched) are the ones worth
# pinning here rather than by booting.
add_host_test(exception_id)
# Firewall exception spec grammar: freestanding header
# (kernel/net/fw_exception.h), no kernel TU. Fail-closed parser — the
# rejection cases are the load-bearing half.
add_host_test(fw_exception)
add_host_test(damage_rect)
# Banded damage / forced-invalidation fold: freestanding constexpr state
# on DamageBandSet in kernel/drivers/video/framebuffer.h — no kernel TU.
add_host_test(damage_bands)
# Intel 2D BLT surface/rectangle gate and packet encoding are pure; the
# actual MMIO submitter remains gated to real Intel silicon.
add_host_test(intel_blt)
add_host_test(render_stats)
target_sources(test_render_stats PRIVATE
    "${CMAKE_SOURCE_DIR}/../../kernel/drivers/video/render_stats.cpp"
)

# ECDSA P-256/P-384 verify — compiles the real kernel crypto TUs and
# runs their EcSelfTest natively (replaces the ~200 s under-TCG boot
# copy; that stays gated behind `selftests=full`).
add_host_test(ec)
target_sources(test_ec PRIVATE
    "${CMAKE_SOURCE_DIR}/../../kernel/net/ec.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/bigint.cpp"
)

# X.509 chain verify (HTTPS trust path) — the heaviest boot crypto
# self-test (RSA-4096 + ECDSA + 8 real roots). Hosted native, gating
# every PR; the in-kernel copy stays behind `selftests=full`.
add_host_test(x509_verify)
target_sources(test_x509_verify PRIVATE
    "${CMAKE_SOURCE_DIR}/../../kernel/net/x509_verify.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/net/ec.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/bigint.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/rsa.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/asn1.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/x509.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/sha256.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/sha384.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/util/datetime.cpp"
)
# x509_verify.cpp documents the OpenSSL fixture-generation commands in
# `//` comments with trailing `\` shell continuations, which trips the
# host build's stricter -Wcomment (the kernel build doesn't enable it).
# These are intentional command documentation, not a code defect, so
# suppress -Wcomment for this target rather than reflow security-critical
# crypto source.
if(NOT MSVC)
    target_compile_options(test_x509_verify PRIVATE -Wno-comment)
endif()

# X25519 (Curve25519 ECDH) — the TLS 1.3 key-exchange primitive. RFC 7748
# §5.2 + §6.1 vectors. Pure field arithmetic, no kernel deps.
add_host_test(x25519)
target_sources(test_x25519 PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/crypto/x25519.cpp")
if(NOT MSVC)
    target_compile_options(test_x25519 PRIVATE -Wno-conversion -Wno-sign-conversion)
endif()

# RSASSA-PSS / SHA-256 verify — the TLS 1.3 RSA CertificateVerify scheme.
# OpenSSL-generated vector (positive + tamper negatives).
add_host_test(rsa_pss)
target_sources(test_rsa_pss PRIVATE
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/rsa.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/bigint.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/crypto/sha256.cpp"
)
if(NOT MSVC)
    target_compile_options(test_rsa_pss PRIVATE -Wno-conversion -Wno-sign-conversion)
endif()

add_host_test(wild_address)
add_host_test(disk_path)
add_host_test(nospec)
add_host_test(saturating)
add_host_test(vfs_resolve)
add_host_test(registry_path)
add_host_test(forwarder)
add_host_test(thunk_hash)
add_host_test(blend)
add_host_test(shadow_atlas)
add_host_test(motion_math)
add_host_test(chrome_text_measure)
add_host_test(app_palette)
add_host_test(app_widgets_bounds)
add_host_test(app_widgets_paint)
add_host_test(app_widgets_events)
add_host_test(widget_group)

# kernel32.dll NLS number-format core (GetNumberFormat / GetCurrencyFormat).
# The header under test is header-only; its authoritative warning gate is
# the freestanding DLL build (-Wall -Wextra -Wpedantic -Werror, no
# -Wconversion), so relax the host harness's extra -Wconversion/
# -Wsign-conversion here — they only fire on legitimate char-index math.
add_host_test(kernel32_nls)
if(NOT MSVC)
    target_compile_options(test_kernel32_nls PRIVATE -Wno-conversion -Wno-sign-conversion)
endif()

# PE `.rsrc` resource-directory walker (userland/libs/common/pe_resources.h):
# the three-level tree, string-table bundling, and the malformed-input
# cases that must fail closed. Same header-only warning-gate reasoning as
# kernel32_nls above — the synthetic-image builder is dense index math.
add_host_test(pe_resources)
if(NOT MSVC)
    target_compile_options(test_pe_resources PRIVATE -Wno-conversion -Wno-sign-conversion)
endif()

# Icon / cursor decoder (duet_res_pick_icon, duet_res_decode_icon).
# Synthetic PE with hand-crafted RT_GROUP_ICON + RT_ICON resources.
add_host_test(pe_icon_decode)
if(NOT MSVC)
    target_compile_options(test_pe_icon_decode PRIVATE -Wno-conversion -Wno-sign-conversion)
endif()

# Delay-load import descriptor walk (kernel/loader/pe_delay_import.h):
# the directory-head bound, per-descriptor truncation, the all-zero
# terminator, and every form the binder must refuse rather than trust.
add_host_test(pe_delay_import)

# Win32 SxS assembly-manifest parser (kernel/loader/manifest.h +
# manifest.cpp): execution level, DPI awareness, long-path awareness,
# SxS dependency extraction, and end-to-end PE resource extraction.
add_host_test(manifest)
target_sources(test_manifest PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/loader/manifest.cpp")
if(NOT MSVC)
    target_compile_options(test_manifest PRIVATE -Wno-conversion -Wno-sign-conversion)
endif()

# Browser omnibox URL-vs-search classifier (kernel/apps/browser/omnibox_classify.h).
add_host_test(omnibox_classify)

# KMalloc small-allocation slab-routing decision logic (kernel/mm/kmalloc_route.h):
# size-class boundaries, route-header encode/decode, KFree discrimination verdicts.
add_host_test(kmalloc_route)

# Autonomic-policy safety shield (kernel/env/policy_shield.h): ShieldConfig
# defaults, the one-call master toggle, ShieldApply rule-floor passthrough,
# and the autonomic=/shields= cmdline parse (incl. prefix-collision guard).
add_host_test(policy_shield)

# Fixed-point neural autonomic policy (kernel/env/neural_policy.cpp): the
# integer forward pass (matmul + >>12 requantize + ReLU), feature
# extraction, and imitation-by-construction (net == rule level-predicates).
add_host_test(neural_policy)
target_sources(test_neural_policy PRIVATE "${CMAKE_SOURCE_DIR}/../../kernel/env/neural_policy.cpp")

# TPM 2.0 wire marshalling (kernel/drivers/tpm/tpm_wire.h): big-endian
# framing, the commandSize back-patch, byte-exact command encodings, and
# hostile-reply rejection. Also pins the sealing-only allow-list: the
# identity-half opcodes (Quote, Certify, ActivateCredential, GetTime, ...)
# must stay refused, so this test fails if anyone adds attestation.
add_host_test(tpm_wire)

# Kernel command-line token parser (kernel/util/cmdline.h): key=value
# lookup incl. prefix collisions, and the strict hex decoder that the TPM
# measured-boot baseline (tpm.baseline=) depends on.
add_host_test(cmdline)

# Font registry (kernel/subsystems/graphics/font.cpp + font8x8.cpp):
# lookup logic, built-in registration, case-insensitive name match,
# height-based fallback, and LookupGlyph dispatch.
add_host_test(font_registry)
target_sources(test_font_registry PRIVATE
    "${CMAKE_SOURCE_DIR}/../../kernel/subsystems/graphics/font.cpp"
    "${CMAKE_SOURCE_DIR}/../../kernel/drivers/video/font8x8.cpp"
)
