// Link stubs for the kernel console-write functions referenced
// by EdidDumpToConsole / Cea861DumpToConsole. The fuzz harness
// drives the parser entry points (EdidParseBaseBlock /
// Cea861ParseBlock); the Dump helpers are only invoked from
// shell commands and boot self-tests, which the host harness
// never reaches. No-op stubs satisfy the linker; a hostile
// input that somehow re-enters Dump would simply print nothing,
// which is correct behaviour under fuzz.

#include "util/types.h"

namespace duetos::drivers::video
{

void ConsoleWrite(const char*) {}
void ConsoleWriteln(const char*) {}

} // namespace duetos::drivers::video
