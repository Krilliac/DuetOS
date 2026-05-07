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

const char* ClassifyWildAddress(u64 value)
{
    // Patterns are checked from most-specific to least-specific.
    // Each branch returns a stable short string the operator can
    // grep for in the dump tooling.

    if (value == 0)
    {
        return "null pointer — uninitialised function pointer or NULL deref";
    }

    if (value == 0xFFFFFFFFFFFFFFFFULL)
    {
        // The classic "wild branch to -1" pattern: a `ret` popped a
        // -1 off a corrupted stack, or a callee-saved register that
        // a Rust/C++ ABI mismatch left holding a sentinel got
        // restored into RIP. Also lands when the IDT was zeroed
        // (every gate target = 0xFFFFFFFFFFFFFFFF after sign-extend).
        return "all-ones (-1) — wild branch / corrupted return address / IDT-uninit jump";
    }

    if (value == 0x00000000FFFFFFFFULL)
    {
        // A u32 sentinel (kKindMiss = 0xFFFFFFFF, kInvalidNodeId,
        // kBootHandleSentinel, kInvalidMountId, etc.) zero-extended
        // to a pointer. A common bug shape: "I forgot to check the
        // -1 return code before using it as an index/handle/ptr".
        return "u32 -1 zero-extended — sentinel (kInvalid* / kKindMiss) used as pointer";
    }

    if (value == 0xFFFFFFFF00000000ULL)
    {
        return "high half all-ones, low zero — sign-extended u32 cast through";
    }

    // Uninit / poison fills planted by allocators or debug runtimes.
    // Recognising them turns "what is 0xCC…CC?" from a guess into a
    // mechanical answer.
    if (value == 0xCCCCCCCCCCCCCCCCULL)
    {
        return "0xCC fill — MSVC debug-stack uninit pattern";
    }
    if (value == 0xCDCDCDCDCDCDCDCDULL)
    {
        return "0xCD fill — MSVC debug-heap uninit pattern";
    }
    if (value == 0xDEADBEEFDEADBEEFULL || value == 0x00000000DEADBEEFULL)
    {
        return "0xDEADBEEF — explicit poison marker";
    }
    if (value == 0xDEADC0DEDEADC0DEULL || value == 0x00000000DEADC0DEULL)
    {
        return "0xDEADC0DE — explicit poison marker";
    }
    if (value == 0xBAADF00DBAADF00DULL)
    {
        return "0xBAADF00D — uninit-heap fill (LocalAlloc)";
    }
    if (value == 0xFEEEFEEEFEEEFEEEULL)
    {
        return "0xFEEEFEEE — freed-heap fill";
    }

    // Every byte == 0xAA is the project's `kStackPoisonByte` (see
    // mm/kstack.cpp); landing in RIP/RBP means a stack-poisoned
    // slot was treated as an instruction or frame pointer.
    if (value == 0xAAAAAAAAAAAAAAAAULL)
    {
        return "0xAA fill — kernel stack poison (kStackPoisonByte)";
    }

    // Non-canonical addresses can't be dereferenced; surfacing this
    // explicitly avoids a confused reader assuming "valid 64-bit
    // pointer" when bits 47..63 don't sign-extend correctly.
    {
        const u64 high = value >> 47;
        // Canonical iff the top 17 bits are all-zero or all-one.
        if (high != 0 && high != 0x1FFFFULL)
        {
            return "non-canonical — top 17 bits not sign-extended (CPU would #GP on deref)";
        }
    }

    // Low values that obviously aren't pointers but get shoved into a
    // ptr slot from time to time (e.g. a u32 errno cast to a fn ptr).
    if (value < 0x10000ULL)
    {
        return "small integer in pointer slot — likely an errno / index / sentinel cast through";
    }

    return nullptr;
}

void WriteWildAddressHint(u64 value)
{
    const char* hint = ClassifyWildAddress(value);
    if (hint == nullptr)
    {
        return;
    }
    arch::SerialWrite("  [wild: ");
    arch::SerialWrite(hint);
    arch::SerialWrite("]");
}

void WriteAddressWithSymbol(u64 addr)
{
    arch::SerialWriteHex(addr);
    SymbolResolution res{};
    if (ResolveAddress(addr, &res))
    {
        WriteResolvedAddress(res);
        return;
    }
    // No symbol matched. If the value is a known sentinel /
    // uninit-fill pattern, emit a `[wild: …]` hint so the operator
    // sees "RIP=0xFFFFFFFFFFFFFFFF [wild: all-ones …]" instead of
    // having to recognise the magic number themselves.
    WriteWildAddressHint(addr);
}

} // namespace duetos::core
