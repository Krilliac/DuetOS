#pragma once

/*
 * Cross-TU surface for the Linux BSD socket family. Handlers live
 * in syscall_socket.cpp and are dispatched from syscall.cpp's main
 * switch. The corresponding Win32 (ws2_32) thunks land in
 * subsystems/win32/winsock_syscall.cpp and reach the same socket
 * pool through its own native SYS_* numbers.
 *
 * Read / write / close on a socket fd dispatch through state==6
 * arms in syscall_io.cpp / syscall_file.cpp respectively.
 */

#include "util/types.h"

namespace duetos::subsystems::linux::internal
{

// AF_INET = 2, SOCK_STREAM = 1, SOCK_DGRAM = 2, SOCK_NONBLOCK = 0x800,
// SOCK_CLOEXEC = 0x80000. The handler masks off the upper SOCK_*
// flags before passing the type to the kernel socket layer.
i64 DoSocket(u64 domain, u64 type, u64 protocol);
i64 DoBind(u64 fd, u64 user_addr, u64 addrlen);
i64 DoListen(u64 fd, u64 backlog);
i64 DoAccept(u64 fd, u64 user_addr, u64 user_addrlen);
i64 DoAccept4(u64 fd, u64 user_addr, u64 user_addrlen, u64 flags);
i64 DoConnect(u64 fd, u64 user_addr, u64 addrlen);
i64 DoSendto(u64 fd, u64 user_buf, u64 len, u64 flags, u64 user_dest_addr, u64 addrlen);
i64 DoRecvfrom(u64 fd, u64 user_buf, u64 len, u64 flags, u64 user_src_addr, u64 user_addrlen);
i64 DoSendmsg(u64 fd, u64 user_msg, u64 flags);
i64 DoRecvmsg(u64 fd, u64 user_msg, u64 flags);
i64 DoShutdown(u64 fd, u64 how);
i64 DoGetsockname(u64 fd, u64 user_addr, u64 user_addrlen);
i64 DoGetpeername(u64 fd, u64 user_addr, u64 user_addrlen);
i64 DoSetsockopt(u64 fd, u64 level, u64 optname, u64 user_optval, u64 optlen);
i64 DoGetsockopt(u64 fd, u64 level, u64 optname, u64 user_optval, u64 user_optlen);
i64 DoSocketpair(u64 domain, u64 type, u64 protocol, u64 user_sv);

// SocketRead / SocketWrite — called from syscall_io.cpp's DoRead /
// DoWrite when state == 6. Keeps the per-state dispatch identical
// in shape to PipeRead / PipeWrite / EventfdRead / EventfdWrite.
i64 SocketFdRead(u32 idx, u64 user_dst, u64 len);
i64 SocketFdWrite(u32 idx, u64 user_src, u64 len);

// Called from syscall_file.cpp's DoClose dispatch arm.
void SocketFdRelease(u32 idx);

// Called from syscall_clone.cpp's DoFork to bump the refcount on
// each socket the parent has open so the child inherits live
// handles. v0 doesn't handle CLOEXEC — every socket survives fork.
void SocketFdRetain(u32 idx);

} // namespace duetos::subsystems::linux::internal
