# Host unit tests for VMM logic units that do not create a live WHP
# partition (mb2 builder, processor contract, ps2 encode, vmm_control,
# ELF/symbol/record parsers, gdb packet decode).
# Sources are added incrementally as tasks land them.
add_executable(vmm-tests
    test_main.cpp
    test_smoke.cpp
    test_mb2_fb.cpp
    test_fb_region.cpp
    test_ps2_encode.cpp
    test_i8042.cpp
    test_mmio_decode.cpp
    test_processor_contract.cpp
    test_vmm_dbg.cpp
    test_elf64_parse.cpp
    test_elf_symbols_load.cpp
    test_record.cpp
    test_gdb_packet.cpp
    ../src/multiboot2.cpp
    ../src/guest_memory_fb.cpp
    ../src/input/ps2_encode.cpp
    ../src/devices/ps2_i8042.cpp
    ../src/mmio_decode.cpp
    ../src/elf64_parse.cpp
    ../src/processor_contract.cpp
    ../src/debug/elf_symbols.cpp
    ../src/debug/record.cpp
    ../src/debug/gdb_packet.cpp
    ../src/debug/vmm_dbg.cpp
)
target_include_directories(vmm-tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
if(MSVC)
    target_compile_options(vmm-tests PRIVATE /W4 /permissive- /EHsc
        /wd4127)   # C4127: do { } while(0) in CHECK macros — false positive
    target_compile_definitions(vmm-tests PRIVATE
        NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS
        VMM_DBG_NO_LIVE)   # exclude LiveResolver (WHP dependency) from test build
endif()
add_test(NAME vmm-tests COMMAND vmm-tests)
