#include "syscall/syscall_names.h"

namespace duetos::core
{

const char* SyscallNumberName(u64 nr)
{
    for (const auto& e : kSyscallNames)
    {
        if (e.nr == nr)
            return e.name;
    }
    return nullptr;
}

} // namespace duetos::core
