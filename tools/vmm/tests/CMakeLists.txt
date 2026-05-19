# Host unit tests for VMM logic units that have NO WHP/Win32
# dependency (mb2 builder, iso9660, ps2 encode, vmm_control).
# Sources are added incrementally as tasks land them.
add_executable(vmm-tests
    test_main.cpp
    test_smoke.cpp
    test_mb2_fb.cpp
    test_fb_region.cpp
    test_ps2_encode.cpp
    ../src/multiboot2.cpp
    ../src/guest_memory_fb.cpp
    ../src/input/ps2_encode.cpp
)
target_include_directories(vmm-tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)
if(MSVC)
    target_compile_options(vmm-tests PRIVATE /W4 /permissive- /EHsc
        /wd4127)   # C4127: do { } while(0) in CHECK macros — false positive
    target_compile_definitions(vmm-tests PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
endif()
add_test(NAME vmm-tests COMMAND vmm-tests)
