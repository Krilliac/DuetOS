#include "env/config_proposal.h"

#include "diag/fix_journal.h"
#include "env/config_proposal_decide.h"
#include "syscall/inferred_gap.h"

namespace duetos::env
{

namespace
{

// Bind the allow-list's mirrored current value to the live constant so they
// cannot drift. If kInferredGapPinCap changes, update kConfigKnobTable too —
// this fires at compile time otherwise.
static_assert(kConfigKnobTable[static_cast<unsigned>(ConfigKnob::InferredGapPinCap)].current_value ==
                  ::duetos::syscall::kInferredGapPinCap,
              "config-proposal allow-list drifted from kInferredGapPinCap");

// One proposal per knob per boot — the journal also dedups per source_pin, but
// gating here avoids re-deciding every cycle.
constinit bool g_emitted[static_cast<unsigned>(ConfigKnob::Count)] = {};

// Append a decimal value to `p`; returns the new write cursor.
char* AppendDec(char* p, unsigned long long v)
{
    char tmp[24];
    int n = 0;
    if (v == 0)
        tmp[n++] = '0';
    while (v != 0)
    {
        tmp[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    while (n > 0)
        *p++ = tmp[--n];
    return p;
}

} // namespace

bool EmitConfigProposal(ConfigKnob knob, u32 observed)
{
    const unsigned idx = static_cast<unsigned>(knob);
    if (idx >= static_cast<unsigned>(ConfigKnob::Count) || g_emitted[idx])
        return false;

    const ConfigProposalDecision d = ConfigProposalDecide(knob, observed);
    if (!d.emit)
        return false;

    g_emitted[idx] = true;

    // pin = "config:<symbol>" — the generator keys on the `config:` prefix.
    char pin[48] = "config:";
    char* p = pin + 7;
    for (const char* s = d.symbol; *s != '\0' && p < pin + sizeof(pin) - 1; ++s)
        *p++ = *s;
    *p = '\0';

    // hint = "<current> -> <proposed> (evidence=N)" — human-readable summary
    // the generator copies into the patch comment.
    char hint[64];
    char* h = hint;
    h = AppendDec(h, d.current_value);
    *h++ = ' ';
    *h++ = '-';
    *h++ = '>';
    *h++ = ' ';
    h = AppendDec(h, d.proposed_value);
    const char* tail = " (evidence=";
    for (const char* s = tail; *s != '\0'; ++s)
        *h++ = *s;
    h = AppendDec(h, d.evidence_count);
    *h++ = ')';
    *h = '\0';

    // DATA only — ctx_a = current, ctx_b = proposed. No source write.
    (void)::duetos::diag::FixJournalRecord(::duetos::diag::FixDetector::AutonomicProposal, pin, hint, d.current_value,
                                           d.proposed_value);
    return true;
}

} // namespace duetos::env
