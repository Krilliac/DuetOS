# <Page Title>

> **Audience:** <Kernel hackers | Driver authors | App / PE devs | QA | Mixed>
>
> **Execution context:** <Kernel | Userland | Both | IRQ-safe / sleep-safe / process>
>
> **Maturity:** <v0 (just lands) | active | stable | deprecated>

## Overview

Explain what this subsystem, driver, or guide covers and why it exists. One paragraph.

## When to Use / When to Read

List concrete scenarios where this page is the right reference.

## Threading & Locking Model

Document which operations run in IRQ vs. process context, what locks are held,
whether the surface can sleep, and any IRQ-disable requirements.

## Capability / Privilege Surface

If this subsystem is gated by `kCap*`, list the gates here and link to
[`security/Capabilities.md`](../security/Capabilities.md).

## Key APIs and Types

Provide key classes, structs, and entry points with short purpose notes.
Reference exact paths (e.g. `kernel/mm/address_space.h`).

## Performance Notes

Call out hot paths, allocation behavior, scaling characteristics, and known
worst-case complexities.

## Known Limits / GAPs / STUBs

Itemise what is **not** implemented yet. Anything carrying a `// STUB:` or
`// GAP:` marker in the source belongs here so future audits can find it from
the wiki side too. See `CLAUDE.md` for the marker convention.

## Troubleshooting

Common failure modes and direct fixes.

## Related Pages

Link to adjacent wiki pages and specs.
