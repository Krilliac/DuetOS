// DuetOS — VT/ANSI escape-sequence parser fuzz harness.
//
// ParserFeed runs the DEC ANSI state machine over a terminal
// byte stream: C0 controls, UTF-8 multi-byte join, CSI parameter
// accumulation (bounded param array), and OSC string capture
// (bounded buffer with a truncation flag). The bytes come from
// whatever a program writes to its PTY / the serial console —
// attacker-controlled if a hostile app or remote shell drives
// the terminal. Non-null no-op callbacks are installed so the
// CSI/OSC dispatch arms are reached; ASan + the param/OSC bounds
// catch buffer overruns on adversarial sequences.

#include "util/vt_parser.h"

#include <cstddef>
#include <cstdint>

namespace
{
void OnPrint(void*, duetos::u32) {}
void OnExecute(void*, duetos::u8) {}
void OnCsi(void*, char, char, const duetos::u16*, duetos::u32) {}
void OnOsc(void*, duetos::u32, const char*, duetos::u32) {}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > (1u << 20))
        return 0;

    duetos::util::vt::Callbacks cb{};
    cb.cookie = nullptr;
    cb.print = &OnPrint;
    cb.execute = &OnExecute;
    cb.csi = &OnCsi;
    cb.osc = &OnOsc;

    duetos::util::vt::Parser p{};
    duetos::util::vt::ParserInit(p, cb);
    (void)duetos::util::vt::ParserFeed(p, reinterpret_cast<const duetos::u8*>(data), static_cast<duetos::u32>(size));
    return 0;
}
