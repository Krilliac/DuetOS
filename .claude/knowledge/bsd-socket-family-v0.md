# BSD socket family v0 — DuetOS

**Type:** Observation + Decision
**Status:** Active
**Last updated:** 2026-04-27

## What landed

Real BSD socket family for the Linux ABI subsystem on top of an
8-slot kernel-resident socket pool. AF_INET + SOCK_DGRAM and
AF_INET + SOCK_STREAM both reachable through the standard
`socket(2)` / `bind(2)` / `connect(2)` / `sendto(2)` / `recvfrom(2)`
/ `accept(2)` / `listen(2)` / `shutdown(2)` / `getsockname(2)` /
`getpeername(2)` / `setsockopt(2)` / `getsockopt(2)` /
`sendmsg(2)` / `recvmsg(2)` syscalls. fork() inherits every fd
including sockets, pipes, eventfds — refcounts bumped per state
in `syscall_clone.cpp::DoFork`.

## Files

- `kernel/net/socket.h` — public surface, ~190 lines
- `kernel/net/socket.cpp` — pool + RX dispatch + TCP integration, ~440 lines
- `kernel/subsystems/linux/syscall_socket.{h,cpp}` — Linux ABI handlers + LinuxFd dispatch arms
- `kernel/proc/process.h` — LinuxFd state docstring updated (state 6 = socket)
- `kernel/subsystems/linux/syscall_io.cpp` — DoRead / DoWrite state==6 arms
- `kernel/subsystems/linux/syscall_file.cpp` — DoClose state==6 arm
- `kernel/subsystems/linux/syscall.cpp` — kSysSocket / kSysBind / ... dispatch (replacing the previous `-ENETDOWN` / `-EBADF` fall-through)
- `kernel/subsystems/linux/syscall_clone.cpp` — DoFork now copies parent fd table + retains pool refs
- `kernel/subsystems/linux/syscall_pipe.{h,cpp}` — added `PipeRetainRead` / `PipeRetainWrite` / `EventfdRetain` for fork-inherit
- `kernel/net/stack.{h,cpp}` — added `NetTcpActiveReadAt`, `NetTcpActiveSend`, `NetTcpActiveCloseTx`; UDP demux pre-checks SocketUdpDispatch; TCP RX wakes SocketTcpRxNotify
- `kernel/syscall/syscall.{h,cpp}` — added `SYS_SOCKET_OP = 153` (multi-op shape, matches SYS_REGISTRY) with kCapNet gate; cap-gated dispatch covers kSockOpCreate / kSockOpBind / kSockOpConnect / kSockOpListen / kSockOpAccept / kSockOpSendto / kSockOpRecvfrom / kSockOpShutdown / kSockOpClose / kSockOpGetSock / kSockOpGetPeer
- `userland/libs/ws2_32/ws2_32.c` — Winsock thunks rewritten to `int 0x80` SYS_SOCKET_OP via the `ws2_op` asm trampoline; wsa_translate_errno maps Linux errno → WSAExxx; WSAStartup returns success (was: WSAENETDOWN); WSAGetLastError reflects last failure
- `kernel/CMakeLists.txt` — ws2_32 export list extended (inet_ntoa, inet_pton, inet_ntop, htonll, ntohll, WSAEnumProtocolsA/W, getnameinfo, WSAIoctl, ioctlsocket, getsockname, getpeername)

## Architecture

Pool capacity = 8 sockets, refcounted (`Socket::refs`). UDP RX
queue is per-socket (8 datagrams × 1500 bytes each, KMalloc'd at
SocketAlloc time). TCP shares the single-slot active-connect
machine in `stack.cpp` (only one socket can hold
`tcp_owner_token` at a time).

UDP RX path: `NetUdpDispatch` → `SocketUdpDispatch` → matching
socket's RX queue. The legacy `UdpBinding` table only fires when
no socket consumed the datagram (kernel-resident DHCP / DNS /
NTP callers stay on the legacy path).

TCP send-after-establish: new `NetTcpActiveSend` ships a data
segment from the user buffer, advances `snd_next`. Only valid
in role=Client + state=Established.

`shutdown(SHUT_WR)` on a TCP socket calls `NetTcpActiveCloseTx`
(emits FIN, transitions to LastAck).

## Sub-GAPs (intentional)

| Gap | Why deferred |
|---|---|
| `SOCK_NONBLOCK` / `SOCK_CLOEXEC` accepted but ignored | Non-blocking I/O is part of the epoll slice |
| Concurrent TCP connections (≥ 2 Established) | Stack has one TcpConn slot; full slot refactor is its own slice |
| TCP send-after-establish on **server** (passive-listen) path | NetTcp*Server* equivalents need adding |
| `accept(2)` polls instead of blocking on a wait queue | Listening socket → accepted fd handover wiring would need its own state machine |
| `getpeername` on accepted fd returns 0.0.0.0 | NetTcpActiveSnapshot doesn't expose peer endpoint |
| `setsockopt` / `getsockopt` are accept-and-ignore | SO_REUSEADDR / SO_BROADCAST / SO_RCVTIMEO not honoured |
| `sendmmsg` / `recvmmsg` return -ENOSYS | v0 forwards just one mmsghdr; batch shape needs caller iteration |
| `socketpair(2)` returns -EOPNOTSUPP | AF_UNIX deferred; AF_INET socketpair isn't on Linux |
| TCP buffer is shared across all SOCK_STREAM sockets | One Established slot ⇒ one buffer ⇒ one read cursor (g_tcp_consumed[idx]) |
| ws2_32 winsock thunks not yet wired to SYS_SOCK_* | Win32 surface still falls through to the legacy stub paths |
| `fcntl(F_SETFL, O_NONBLOCK)` on a socket fd is a no-op | Same root cause as SOCK_NONBLOCK |

## What this unlocks

- glibc / musl ELF binaries that issue `socket(AF_INET, SOCK_DGRAM, 0)` + `sendto` + `recvfrom` — full UDP loop
- `nc -u`-shape probes
- DNS / NTP from user-mode (talking through the same RX path as the kernel-resident clients)
- Any TCP client doing `connect → send → recv → close`
- The fork+pipe shell pipeline now actually inherits fds — `parent_fork() → child_exec("ls")` with the parent's fd 1 hooked to a pipe will deliver bytes to the parent's fd 0 reader

## Follow-ups

1. Socketpair / AF_UNIX (cross-process loopback ring)
2. epoll integration so socket fds fire EPOLLIN
3. Full multi-connection TCP (refactor TcpConn into a pool)
4. Win32 ws2_32 thunks → SYS_SOCK_* (would let WinPE binaries use sockets)
5. recvfrom timeout / non-blocking semantics

## Verification

```
cmake --preset x86_64-debug
cmake --build build/x86_64-debug --parallel 4
```

Linked clean. End-to-end runtime smoke needs QEMU + a Linux ELF
that exercises the syscalls — not yet on the dev host.
