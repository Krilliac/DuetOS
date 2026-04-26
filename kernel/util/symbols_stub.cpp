#include "util/symbols.h"

/*
 * Stage-1 stub symbol table.
 *
 * Compiled into `duetos-kernel-stage1.elf`, which is a temporary
 * kernel image we only build so `tools/build/gen-symbols.sh` can read its
 * symbol addresses and emit the real table. The final kernel replaces
 * this TU with `symbols_generated.cpp`.
 *
 * The stub intentionally has no real data — the populated table is
 * many KiB of string pool + entries. As long as the populated TU is
 * placed LAST in the kernel source list (so its .rodata sits at the
 * end of .rodata), every other symbol in the stage-1 ELF keeps the
 * same runtime VA in the stage-2 kernel. That is what makes the
 * extracted table accurate for the final image.
 */

namespace duetos::core
{

extern "C" const SymbolEntry g_duetos_symtab_entries[1] = {{0, 0, 0, "??", "??"}};
extern "C" const u64 g_duetos_symtab_count = 0;

} // namespace duetos::core
