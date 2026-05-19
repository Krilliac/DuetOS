// Vmm introspection surface (split out of vmm.cpp to keep that TU
// focused on VM orchestration). Symbol-backed, no struct-layout
// coupling: resolve names<->addresses, hexdump a named global,
// symbolize an address/RIP, and replay the vmexit ring. Reached
// via the gdb `monitor` command (slice 3 transport) and the
// on-fatal auto-dump.
#include <cstdio>
#include <cstring>
#include <string>

#include "vmm.h"

namespace duetos::vmm
{

void Vmm::RecordExit(const WHV_RUN_VP_EXIT_CONTEXT& exit)
{
    uint64_t aux = 0;
    switch (exit.ExitReason)
    {
    case WHvRunVpExitReasonX64IoPortAccess:
        aux = exit.IoPortAccess.PortNumber;
        break;
    case WHvRunVpExitReasonMemoryAccess:
        aux = exit.MemoryAccess.Gpa;
        break;
    case WHvRunVpExitReasonException:
        aux = exit.VpException.ExceptionType;
        break;
    default:
        break;
    }
    m_trace.Record(static_cast<uint32_t>(exit.ExitReason),
                   exit.VpContext.Rip, aux);
}

void Vmm::DumpTrace(std::string& out) const
{
    char line[256];
    m_trace.ForEach([&](const ExitTrace::Entry& e) {
        std::snprintf(line, sizeof(line),
                      "  #%llu reason=%u aux=0x%llx rip=%s\n",
                      (unsigned long long)e.seq, e.reason,
                      (unsigned long long)e.aux,
                      m_symbols.Symbolize(e.rip).c_str());
        out += line;
    });
}

std::string Vmm::Monitor(const std::string& cmd)
{
    char tok[64] = {};
    unsigned long long arg = 0;
    std::sscanf(cmd.c_str(), "%63s", tok);
    std::string t = tok;

    if (t == "help" || t.empty())
    {
        return "monitor commands:\n"
               "  sym <hexaddr>      nearest kernel symbol\n"
               "  lookup <name>      symbol addr+size\n"
               "  read <name> [n]    hexdump n bytes of a symbol\n"
               "  rip                symbolize current RIP\n"
               "  trace              recent vmexit ring\n";
    }
    if (t == "rip")
    {
        return m_symbols.Symbolize(m_part.GetRip(0)) + "\n";
    }
    if (t == "trace")
    {
        std::string out;
        DumpTrace(out);
        return out.empty() ? "(no exits yet)\n" : out;
    }
    if (t == "sym")
    {
        if (std::sscanf(cmd.c_str(), "%*s %llx", &arg) != 1)
        {
            return "usage: sym <hexaddr>\n";
        }
        return m_symbols.Symbolize(arg) + "\n";
    }
    if (t == "lookup" || t == "read")
    {
        char name[128] = {};
        if (std::sscanf(cmd.c_str(), "%*s %127s", name) != 1)
        {
            return "usage: " + t + " <name>\n";
        }
        const ElfSymbols::Sym* s = m_symbols.Find(name);
        if (!s)
        {
            return std::string("symbol not found: ") + name + "\n";
        }
        char hdr[160];
        std::snprintf(hdr, sizeof(hdr),
                      "%s addr=0x%llx size=%llu\n", name,
                      (unsigned long long)s->addr,
                      (unsigned long long)s->size);
        if (t == "lookup")
        {
            return hdr;
        }
        uint64_t n = s->size ? s->size : 16;
        std::sscanf(cmd.c_str(), "%*s %*s %llu", &arg);
        if (arg)
        {
            n = arg;
        }
        if (n > 256)
        {
            n = 256; // bounded console dump
        }
        std::string out = hdr;
        char b[8];
        for (uint64_t i = 0; i < n; ++i)
        {
            uint64_t gpa = 0;
            if (!m_part.TranslateGva(0, s->addr + i, gpa))
            {
                out += " <unmapped>";
                break;
            }
            uint8_t* p =
                static_cast<uint8_t*>(m_mem->HostPtr(gpa, 1));
            if (!p)
            {
                out += " <oob>";
                break;
            }
            std::snprintf(b, sizeof(b), "%02x ", *p);
            out += b;
            if ((i & 15) == 15)
            {
                out += "\n";
            }
        }
        out += "\n";
        return out;
    }
    return "unknown command (try: help)\n";
}

} // namespace duetos::vmm
