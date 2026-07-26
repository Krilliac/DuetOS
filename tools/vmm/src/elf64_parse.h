// Pure ELF64 header + program-header validation.
//
// Split out of elf64.cpp so the host test binary can exercise it against
// hostile inputs without a WHP partition or guest RAM: this TU has no
// I/O, no GuestMemory, and no Windows dependency (see
// tests/test_elf64_parse.cpp). elf64.cpp keeps the part that actually
// blits bytes into the guest.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace duetos::vmm
{

struct LoadSegment
{
    uint64_t offset = 0; // p_offset — validated to lie inside the image
    uint64_t paddr  = 0; // p_paddr  — load address (LMA)
    uint64_t filesz = 0; // p_filesz — bytes to copy from the image
    uint64_t memsz  = 0; // p_memsz  — >= filesz; the tail is .bss
};

struct ParsedElf
{
    uint64_t                 entry     = 0;
    uint64_t                 lowPaddr  = 0;
    uint64_t                 highPaddr = 0; // max(p_paddr + p_memsz)
    std::vector<LoadSegment> segments;
};

// Validates the ELF64 header and every PT_LOAD program header of the
// `size`-byte image at `buf`, appending the loadable segments to `out`.
// Returns false and fills `err` with a human-readable reason on any
// malformed or unsupported input.
//
// Every range test is a subtraction against `size` rather than an
// addition compared to it, so a hostile p_offset/p_filesz pair cannot
// wrap past the check.
bool ParseElf64(const uint8_t* buf, size_t size, ParsedElf& out,
                std::string& err);

} // namespace duetos::vmm
