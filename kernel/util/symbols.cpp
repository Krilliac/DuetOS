#include "util/symbols.h"

#include "arch/x86_64/serial.h"

/*
 * Symbol-table access path. The table itself lives in a generated
 * translation unit — either `symbols_generated.cpp` (stage 2, real
 * data) or `symbols_stub.cpp` (stage 1, empty data). Both forms
 * define the three external linkage symbols referenced below.
 */

namespace duetos::core
{

extern "C" const SymbolEntry g_duetos_symtab_entries[];
extern "C" const u64 g_duetos_symtab_count;

namespace
{

// Write an unsigned decimal. Good enough for line numbers — we never
// expect more than 8 digits, so no need for a general-purpose formatter.
void WriteDec(u64 value)
{
    if (value == 0)
    {
        arch::SerialWriteByte('0');
        return;
    }
    char buf[20];
    int len = 0;
    while (value > 0)
    {
        buf[len++] = static_cast<char>('0' + (value % 10));
        value /= 10;
    }
    while (len-- > 0)
    {
        arch::SerialWriteByte(static_cast<u8>(buf[len]));
    }
}

// Write an offset as a compact hex literal — "0x0" for zero, otherwise
// the minimum number of hex digits. Keeps dump lines readable.
void WriteCompactHex(u64 value)
{
    static constexpr char kDigits[] = "0123456789abcdef";
    arch::SerialWriteByte('0');
    arch::SerialWriteByte('x');
    if (value == 0)
    {
        arch::SerialWriteByte('0');
        return;
    }
    int shift = 60;
    while (shift > 0 && ((value >> shift) & 0xF) == 0)
    {
        shift -= 4;
    }
    for (; shift >= 0; shift -= 4)
    {
        arch::SerialWriteByte(static_cast<u8>(kDigits[(value >> shift) & 0xF]));
    }
}

} // namespace

bool ResolveAddress(u64 addr, SymbolResolution* out)
{
    if (out == nullptr)
    {
        return false;
    }
    out->entry = nullptr;
    out->offset = 0;

    const u64 count = g_duetos_symtab_count;
    if (count == 0)
    {
        return false;
    }

    // Binary search for the largest entry whose addr <= query.
    // Entries are strictly sorted by addr by the generator.
    u64 lo = 0;
    u64 hi = count;
    while (lo < hi)
    {
        const u64 mid = lo + (hi - lo) / 2;
        if (g_duetos_symtab_entries[mid].addr <= addr)
        {
            lo = mid + 1;
        }
        else
        {
            hi = mid;
        }
    }
    if (lo == 0)
    {
        return false; // query is below the lowest symbol
    }

    const SymbolEntry& cand = g_duetos_symtab_entries[lo - 1];
    const u64 offset = addr - cand.addr;

    // A size of 0 means "unknown extent" — only match if the query is
    // exactly the symbol's entry address. Otherwise require offset to
    // lie inside the reported extent, plus a single byte of slack:
    // `__builtin_return_address(0)` on a call to a [[noreturn]]
    // function points one byte past the caller's claimed end (the
    // byte AFTER the trailing `call` instruction). We treat that
    // post-end slot as still belonging to the caller, which is how
    // addr2line / llvm-symbolizer report it. Anything farther past
    // the end would have hit the next entry in the binary search.
    if (cand.size == 0)
    {
        if (offset != 0)
        {
            return false;
        }
    }
    else if (offset > cand.size)
    {
        return false;
    }

    out->entry = &cand;
    out->offset = offset;
    return true;
}

u64 SymbolTableSize()
{
    return g_duetos_symtab_count;
}

void WriteResolvedAddress(const SymbolResolution& resolution)
{
    if (resolution.entry == nullptr)
    {
        return;
    }
    arch::SerialWrite("  [");
    arch::SerialWrite(resolution.entry->name);
    arch::SerialWrite("+");
    WriteCompactHex(resolution.offset);
    arch::SerialWrite(" (");
    arch::SerialWrite(resolution.entry->file);
    if (resolution.entry->line != 0)
    {
        arch::SerialWrite(":");
        WriteDec(resolution.entry->line);
    }
    arch::SerialWrite(")]");
}

void WriteAddressWithSymbol(u64 addr)
{
    arch::SerialWriteHex(addr);
    SymbolResolution res{};
    if (ResolveAddress(addr, &res))
    {
        WriteResolvedAddress(res);
    }
}

} // namespace duetos::core
