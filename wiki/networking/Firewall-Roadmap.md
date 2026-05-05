# Firewall — Roadmap

DuetOS does not yet ship a packet filter. The Start menu's
**FIREWALL** entry opens an empty-state window
(`kernel/apps/firewall.{h,cpp}`) that documents this gap so users
who expect a Windows-style firewall control panel see an honest
"not installed" message instead of a dead launcher.

## Today

- All bound interfaces are unfiltered. Every packet the NIC
  accepts reaches the L2 / L3 / L4 stack.
- There is no rule table, no zone model, no per-port allow/deny,
  no per-process socket policy.
- The viewer window is read-only.

## Planned scope (not committed yet)

1. **Static rule table.** Fixed-capacity allow/deny list on
   tuple `(direction, protocol, src_addr/mask, dst_addr/mask,
   src_port_range, dst_port_range)`. Default-deny inbound,
   default-allow outbound, mirroring Windows' default.
2. **Hooks at L2 ingress and L3 egress.** Filter runs once per
   packet on each direction; drops increment a per-rule counter.
3. **Editor surface.** Replace the placeholder window with a
   list view + add / remove / toggle controls. Editing requires
   the `kCapNetAdmin` capability (new — to be added alongside).
4. **Per-process policy.** Socket-level filter keyed off the
   owning `Process::caps` so a sandboxed Win32 PE can be denied
   network egress entirely.

The placeholder window stays put until step 1 lands; updating
its body text to reflect new partial-implementation states is
preferred over silently swapping it for an editor that mediates
nothing.
