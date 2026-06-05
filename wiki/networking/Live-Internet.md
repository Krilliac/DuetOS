# Live Internet Verification

> **Audience:** Net stack hackers, evaluators
>
> **Execution context:** Kernel — driver IRQ + socket API
>
> **Maturity:** v0 — DuetOS reaches Google over real DNS + TCP

## Overview

DuetOS's net stack is verified end-to-end by a live boot that reaches
the real Internet. The path:

1. e1000 link comes up (or USB CDC-ECM / RNDIS, if those are
   selected).
2. DHCP OFFER + ACK acquire an IP from the local network.
3. DNS resolver issues a query for `www.google.com`.
4. TCP connect to the resolved IP, port 80.
5. HTTP `GET /` and read the response.
6. Print the HTTP status line on the serial console as proof.

## Why "Live Internet" Is the Bar

Every layer in the stack participates: NIC driver, ARP, IP, UDP (DNS),
TCP, app. A single regression anywhere in the path breaks the
verification. Cheap to run, expensive to fake.

## Where the Code Lives

- `kernel/drivers/net/e1000/` — wired NIC driver
- `kernel/drivers/usb/class/{cdc-ecm,rndis}/` — USB Ethernet
- `kernel/net/` — protocol stacks
- `kernel/shell/` — shell commands that drive verification

## Reproducing

The QEMU smoke harness includes a `-netdev user,model=e1000` route
that reaches the host's network. The smoke entry-point invokes the
HTTP fetch and asserts a 2xx / 3xx response.

## Known Limits / GAPs

- **DNS over UDP only.** No DoT/DoH yet.
- **HTTPS lands** via the in-kernel TLS 1.2 client
  ([TLS Client](TLS-Roadmap.md)) with an embedded root store, so the
  fetch above can run over `https://` as well as plain HTTP. The known
  cert-verification limits (no P-521 / RSA-PSS / Ed25519, depth-2 chain
  cap) live on the TLS page.
- **IPv6 is partial.** `kernel/net/ipv6.cpp` answers ICMPv6 echo and
  link-local Neighbor Discovery, but the transport demux is still
  v4-keyed (`ipv6.cpp:385`, `:403`), so the live verification above runs
  over IPv4. See [Network Stack](Network-Stack.md#known-limits--gaps).

## Related Pages

- [Network Stack](Network-Stack.md)
- [Networking Drivers](../drivers/Networking-Drivers.md)
- [USB](../drivers/USB.md)
