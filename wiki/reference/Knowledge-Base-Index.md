# Knowledge Base Index

> **Audience:** Contributors looking for deeper context
>
> **Maturity:** Replaced by the wiki itself

## Status — consolidated

The previous two-tier documentation model (wiki for "what is" plus
a parallel session-memory directory for terse, slice-numbered
postmortems) was consolidated into a single canonical wiki. Every
entry that earned a permanent home landed in the relevant subsystem
page; everything that didn't was a one-off slice log whose
information is captured in commit messages and the
[Design Decisions](Design-Decisions.md) log.

**Where to look now:**

| Looking for... | Read |
|----------------|------|
| What a subsystem does today | The matching wiki page (start at the [Sidebar](../_Sidebar.md)) |
| What's pending / deferred | [Roadmap](Roadmap.md) |
| Why a subsystem looks the way it does | [Design Decisions](Design-Decisions.md), [History](../getting-started/History.md) |
| The shell command surface | [Shell Commands](Shell-Commands.md) / [Shell Scripting](Shell-Scripting.md) |
| Live `STUB` / `GAP` markers | `git grep -nE "// (STUB\|GAP):"` |
| A failure mode | [Troubleshooting](../advanced/Troubleshooting.md) |

The session-memory tier was retired because (a) most entries were
postmortems whose conclusions had already been folded into the wiki
when the slice landed, and (b) the project's documentation has
matured to the point where a single canonical home reduces
maintenance churn.

## Related Pages

- [Roadmap](Roadmap.md)
- [Design Decisions](Design-Decisions.md)
- [Directory Layout](Directory-Layout.md)
