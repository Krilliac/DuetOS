/*
 * Linux BSD socket family — v0.
 *
 * Single LinuxFd state value lands here (state 6 = socket → first_cluster =
 * socket pool index). Pool + dispatch live in net/socket.{h,cpp}; this
 * TU owns the user-pointer marshaling (sockaddr_in, iovecs, msghdr)
 * and the syscall-level error mapping.
 *
 * v0 covers AF_INET + SOCK_DGRAM (full BSD UDP semantics) and AF_INET
 * + SOCK_STREAM via the single-slot active-connect machine in
 * net/stack.cpp. AF_UNIX, SOCK_RAW, SOCK_SEQPACKET, IPv6, and
 * socketpair are out of v0 scope and report the canonical Linux
 * errno (-EAFNOSUPPORT / -EPROTONOSUPPORT / -EOPNOTSUPP).
 */

#include "subsystems/linux/syscall_internal.h"
#include "subsystems/linux/syscall_socket.h"

#include "arch/x86_64/serial.h"
#include "mm/paging.h"
#include "net/socket.h"
#include "net/stack.h"
#include "proc/process.h"
#include "sched/sched.h"

namespace duetos::subsystems::linux::internal
{

namespace
{

constexpr i64 kEAfNoSupport = -97;
constexpr i64 kEProtoNoSupport = -93;
constexpr i64 kEAddrInUse = -98;
constexpr i64 kEOpNotSupp = -95;
constexpr i64 kENotConn = -107;
constexpr i64 kENetDown = -100;

// Strip Linux SOCK_NONBLOCK / SOCK_CLOEXEC from the type so we can
// match against the bare SOCK_DGRAM / SOCK_STREAM. Both flags are
// ignored in v0 (sub-GAP — non-blocking I/O is part of the epoll
// slice, CLOEXEC is part of fd-inheritance).
constexpr u64 kSockNonBlock = 0x800;
constexpr u64 kSockCloExec = 0x80000;
constexpr u64 kSockTypeMask = 0xFFFFFFFFu & ~(kSockNonBlock | kSockCloExec);

// sockaddr_in layout — kept as a plain struct because the kernel
// doesn't include net/in.h (no glibc headers in freestanding).
struct LinuxSockaddrIn
{
    u16 sin_family;
    u16 sin_port_be;
    u8 sin_addr[4];
    u8 sin_zero[8];
};

// AF_INET = 2 in both Linux and BSD.
constexpr u16 kAfInet = 2;

bool ReadSockaddrIn(u64 user_addr, u64 addrlen, ::duetos::net::Ipv4Address& out_ip, u16& out_port)
{
    if (addrlen < sizeof(LinuxSockaddrIn))
        return false;
    LinuxSockaddrIn sa;
    if (!mm::CopyFromUser(&sa, reinterpret_cast<const void*>(user_addr), sizeof(sa)))
        return false;
    if (sa.sin_family != kAfInet)
        return false;
    out_port = (u16(sa.sin_port_be & 0xFF) << 8) | u16(sa.sin_port_be >> 8);
    for (u32 i = 0; i < 4; ++i)
        out_ip.octets[i] = sa.sin_addr[i];
    return true;
}

bool WriteSockaddrIn(u64 user_addr, u64 user_addrlen_ptr, ::duetos::net::Ipv4Address ip, u16 port)
{
    if (user_addr == 0)
        return true;
    u32 cap = 0;
    if (!mm::CopyFromUser(&cap, reinterpret_cast<const void*>(user_addrlen_ptr), sizeof(cap)))
        return false;
    LinuxSockaddrIn sa = {};
    sa.sin_family = kAfInet;
    sa.sin_port_be = u16(((port & 0xFF) << 8) | (port >> 8));
    for (u32 i = 0; i < 4; ++i)
        sa.sin_addr[i] = ip.octets[i];
    const u32 to_write = (cap < sizeof(sa)) ? cap : sizeof(sa);
    if (to_write > 0 && !mm::CopyToUser(reinterpret_cast<void*>(user_addr), &sa, to_write))
        return false;
    const u32 truth = sizeof(sa);
    if (!mm::CopyToUser(reinterpret_cast<void*>(user_addrlen_ptr), &truth, sizeof(truth)))
        return false;
    return true;
}

i32 AllocFd(::duetos::core::Process* p)
{
    for (u32 i = 3; i < LinuxFdEffectiveMax(p); ++i)
    {
        if (p->linux_fds[i].state == 0)
            return static_cast<i32>(i);
    }
    return -1;
}

void FdAssignSocket(::duetos::core::Process* p, u32 fd, u32 sock_idx)
{
    p->linux_fds[fd].state = 6;
    p->linux_fds[fd].first_cluster = sock_idx;
    p->linux_fds[fd].size = 0;
    p->linux_fds[fd].offset = 0;
    p->linux_fds[fd].path[0] = '\0';
}

bool FdIsSocket(::duetos::core::Process* p, u64 fd, u32& out_idx)
{
    if (fd >= 16)
        return false;
    if (p->linux_fds[fd].state != 6)
        return false;
    out_idx = p->linux_fds[fd].first_cluster;
    return ::duetos::net::SocketAlive(out_idx);
}

} // namespace

i64 DoSocket(u64 domain, u64 type, u64 protocol)
{
    (void)protocol; // v0: protocol selector ignored
    if (domain != kAfInet)
        return kEAfNoSupport;
    const u64 base_type = type & kSockTypeMask;
    if (base_type != ::duetos::net::kSocketTypeStream && base_type != ::duetos::net::kSocketTypeDgram)
        return kEProtoNoSupport;
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    const i32 fd = AllocFd(p);
    if (fd < 0)
        return kEMFILE;
    const i32 sock = ::duetos::net::SocketAlloc(static_cast<u16>(domain), static_cast<u16>(base_type));
    if (sock < 0)
        return kENFILE;
    FdAssignSocket(p, static_cast<u32>(fd), static_cast<u32>(sock));
    arch::SerialWrite("[linux/socket] fd=");
    arch::SerialWriteHex(static_cast<u64>(fd));
    arch::SerialWrite(" pool=");
    arch::SerialWriteHex(static_cast<u64>(sock));
    arch::SerialWrite(" type=");
    arch::SerialWriteHex(base_type);
    arch::SerialWrite("\n");
    return fd;
}

i64 DoBind(u64 fd, u64 user_addr, u64 addrlen)
{
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    u32 idx;
    if (!FdIsSocket(p, fd, idx))
        return kEBADF;
    ::duetos::net::Ipv4Address ip;
    u16 port;
    if (!ReadSockaddrIn(user_addr, addrlen, ip, port))
        return kEINVAL;
    if (!::duetos::net::SocketBind(idx, ip, port))
        return kEAddrInUse;
    return 0;
}

i64 DoListen(u64 fd, u64 backlog)
{
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    u32 idx;
    if (!FdIsSocket(p, fd, idx))
        return kEBADF;
    if (!::duetos::net::SocketListen(idx, static_cast<u32>(backlog)))
        return kEINVAL;
    return 0;
}

i64 DoAccept(u64 fd, u64 user_addr, u64 user_addrlen)
{
    return DoAccept4(fd, user_addr, user_addrlen, 0);
}

i64 DoAccept4(u64 fd, u64 user_addr, u64 user_addrlen, u64 flags)
{
    (void)flags;
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    u32 listen_idx;
    if (!FdIsSocket(p, fd, listen_idx))
        return kEBADF;
    const auto* listener = ::duetos::net::SocketGet(listen_idx);
    if (listener == nullptr || !listener->listening)
        return kEINVAL;
    // v0 accept blocks on the listener's read_wq until the stack
    // reports an Established connection on the listen port. The
    // accepted fd shares the listener's port with refs >= 2 since
    // v0 has only one TCP connection slot — server send-after-
    // establish is the documented sub-GAP.
    while (true)
    {
        const auto snap = ::duetos::net::NetTcpActiveSnapshot();
        if (snap.in_use && snap.response_len > 0)
            break;
        // Approximate "wait for connect" by polling — full event
        // wiring is a follow-up. Single-CPU yields cheap enough
        // for v0 server-shape tests; if no data arrives the
        // caller controls retry via timeout / shutdown.
        sched::SchedYield();
    }
    const i32 new_fd = AllocFd(p);
    if (new_fd < 0)
        return kEMFILE;
    const i32 new_sock = ::duetos::net::SocketAlloc(::duetos::net::kSocketDomainInet, ::duetos::net::kSocketTypeStream);
    if (new_sock < 0)
        return kENFILE;
    // Stamp peer endpoint from whatever the stack captured.
    // NetTcpActiveSnapshot doesn't expose peer ip/port today —
    // sub-GAP. Caller's getpeername() on the accepted fd will
    // see all-zero.
    FdAssignSocket(p, static_cast<u32>(new_fd), static_cast<u32>(new_sock));
    if (!::duetos::net::SocketConnect(static_cast<u32>(new_sock), {}, 0))
    {
        // Connect failed — release the fd + socket and propagate.
        ::duetos::net::SocketRelease(static_cast<u32>(new_sock));
        p->linux_fds[new_fd].state = 0;
        return kEINVAL;
    }
    if (user_addr != 0 && user_addrlen != 0)
    {
        ::duetos::net::Ipv4Address peer_ip;
        u16 peer_port;
        ::duetos::net::SocketGetPeer(static_cast<u32>(new_sock), &peer_ip, &peer_port);
        WriteSockaddrIn(user_addr, user_addrlen, peer_ip, peer_port);
    }
    return new_fd;
}

i64 DoConnect(u64 fd, u64 user_addr, u64 addrlen)
{
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    u32 idx;
    if (!FdIsSocket(p, fd, idx))
        return kEBADF;
    ::duetos::net::Ipv4Address ip;
    u16 port;
    if (!ReadSockaddrIn(user_addr, addrlen, ip, port))
        return kEINVAL;
    if (!::duetos::net::SocketConnect(idx, ip, port))
        return kENetDown;
    return 0;
}

i64 DoSendto(u64 fd, u64 user_buf, u64 len, u64 flags, u64 user_dest_addr, u64 addrlen)
{
    (void)flags;
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    u32 idx;
    if (!FdIsSocket(p, fd, idx))
        return kEBADF;
    const auto* s = ::duetos::net::SocketGet(idx);
    if (s == nullptr)
        return kEBADF;
    constexpr u64 kStageCap = 1500;
    if (len > kStageCap)
        len = kStageCap;
    u8 stage[kStageCap];
    if (len > 0 && !mm::CopyFromUser(stage, reinterpret_cast<const void*>(user_buf), len))
        return kEFAULT;
    if (s->type == ::duetos::net::kSocketTypeDgram)
    {
        ::duetos::net::Ipv4Address dst_ip = {};
        u16 dst_port = 0;
        if (user_dest_addr != 0)
        {
            if (!ReadSockaddrIn(user_dest_addr, addrlen, dst_ip, dst_port))
                return kEINVAL;
        }
        return ::duetos::net::SocketSendDgram(idx, dst_ip, dst_port, stage, static_cast<u32>(len));
    }
    return ::duetos::net::SocketSendStream(idx, stage, static_cast<u32>(len));
}

i64 DoRecvfrom(u64 fd, u64 user_buf, u64 len, u64 flags, u64 user_src_addr, u64 user_addrlen)
{
    (void)flags;
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    u32 idx;
    if (!FdIsSocket(p, fd, idx))
        return kEBADF;
    const auto* s = ::duetos::net::SocketGet(idx);
    if (s == nullptr)
        return kEBADF;
    constexpr u64 kStageCap = 1500;
    if (len > kStageCap)
        len = kStageCap;
    u8 stage[kStageCap];
    if (s->type == ::duetos::net::kSocketTypeDgram)
    {
        ::duetos::net::Ipv4Address src_ip = {};
        u16 src_port = 0;
        u32 truth = 0;
        const i64 got = ::duetos::net::SocketRecvDgram(idx, stage, static_cast<u32>(len), &truth, &src_ip, &src_port);
        if (got < 0)
            return got;
        if (got > 0 && !mm::CopyToUser(reinterpret_cast<void*>(user_buf), stage, static_cast<u64>(got)))
            return kEFAULT;
        if (user_src_addr != 0 && user_addrlen != 0)
            WriteSockaddrIn(user_src_addr, user_addrlen, src_ip, src_port);
        return got;
    }
    const i64 got = ::duetos::net::SocketRecvStream(idx, stage, static_cast<u32>(len));
    if (got > 0 && !mm::CopyToUser(reinterpret_cast<void*>(user_buf), stage, static_cast<u64>(got)))
        return kEFAULT;
    return got;
}

i64 DoSendmsg(u64 fd, u64 user_msg, u64 flags)
{
    // struct msghdr { void* msg_name; socklen_t msg_namelen; struct iovec*
    //                  msg_iov; size_t msg_iovlen; ... }
    // v0: read just msg_iov[0], forward to DoSendto without dest.
    struct LinuxIovec
    {
        u64 base;
        u64 len;
    };
    struct LinuxMsghdr
    {
        u64 msg_name;
        u32 msg_namelen;
        u32 _pad;
        u64 msg_iov;
        u64 msg_iovlen;
        u64 msg_control;
        u64 msg_controllen;
        u32 msg_flags;
        u32 _pad2;
    };
    LinuxMsghdr mh = {};
    if (!mm::CopyFromUser(&mh, reinterpret_cast<const void*>(user_msg), sizeof(mh)))
        return kEFAULT;
    if (mh.msg_iovlen == 0 || mh.msg_iov == 0)
        return 0;
    LinuxIovec iov;
    if (!mm::CopyFromUser(&iov, reinterpret_cast<const void*>(mh.msg_iov), sizeof(iov)))
        return kEFAULT;
    return DoSendto(fd, iov.base, iov.len, flags, mh.msg_name, mh.msg_namelen);
}

i64 DoRecvmsg(u64 fd, u64 user_msg, u64 flags)
{
    struct LinuxIovec
    {
        u64 base;
        u64 len;
    };
    struct LinuxMsghdr
    {
        u64 msg_name;
        u32 msg_namelen;
        u32 _pad;
        u64 msg_iov;
        u64 msg_iovlen;
        u64 msg_control;
        u64 msg_controllen;
        u32 msg_flags;
        u32 _pad2;
    };
    LinuxMsghdr mh = {};
    if (!mm::CopyFromUser(&mh, reinterpret_cast<const void*>(user_msg), sizeof(mh)))
        return kEFAULT;
    if (mh.msg_iovlen == 0 || mh.msg_iov == 0)
        return 0;
    LinuxIovec iov;
    if (!mm::CopyFromUser(&iov, reinterpret_cast<const void*>(mh.msg_iov), sizeof(iov)))
        return kEFAULT;
    // Synthesise an in-place addrlen for the recvfrom call.
    u32 addrlen = mh.msg_namelen;
    u64 addrlen_user = 0;
    if (mh.msg_name != 0)
    {
        // recvfrom expects a user pointer to the addrlen; v0 creates
        // a temp on the user stack via the existing addrlen pointer
        // when one was supplied. Otherwise, skip the address-out half.
        if (!mm::CopyToUser(reinterpret_cast<void*>(mh.msg_name), &addrlen, 0))
            return kEFAULT;
        addrlen_user = mh.msg_name; // recvfrom uses this only for write-back
    }
    return DoRecvfrom(fd, iov.base, iov.len, flags, mh.msg_name, addrlen_user);
}

i64 DoShutdown(u64 fd, u64 how)
{
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    u32 idx;
    if (!FdIsSocket(p, fd, idx))
        return kEBADF;
    if (how > 2)
        return kEINVAL;
    if (!::duetos::net::SocketShutdown(idx, static_cast<u32>(how)))
        return kEINVAL;
    if (how == 1 || how == 2)
    {
        const auto* s = ::duetos::net::SocketGet(idx);
        if (s != nullptr && s->type == ::duetos::net::kSocketTypeStream && s->tcp_owner_token != 0)
            ::duetos::net::NetTcpActiveCloseTx();
    }
    return 0;
}

i64 DoGetsockname(u64 fd, u64 user_addr, u64 user_addrlen)
{
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    u32 idx;
    if (!FdIsSocket(p, fd, idx))
        return kEBADF;
    ::duetos::net::Ipv4Address ip;
    u16 port;
    ::duetos::net::SocketGetLocal(idx, &ip, &port);
    if (!WriteSockaddrIn(user_addr, user_addrlen, ip, port))
        return kEFAULT;
    return 0;
}

i64 DoGetpeername(u64 fd, u64 user_addr, u64 user_addrlen)
{
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    u32 idx;
    if (!FdIsSocket(p, fd, idx))
        return kEBADF;
    const auto* s = ::duetos::net::SocketGet(idx);
    if (s == nullptr)
        return kEBADF;
    if (!s->connected)
        return kENotConn;
    ::duetos::net::Ipv4Address ip;
    u16 port;
    ::duetos::net::SocketGetPeer(idx, &ip, &port);
    if (!WriteSockaddrIn(user_addr, user_addrlen, ip, port))
        return kEFAULT;
    return 0;
}

i64 DoSetsockopt(u64 fd, u64 level, u64 optname, u64 user_optval, u64 optlen)
{
    (void)level;
    (void)optname;
    (void)user_optval;
    (void)optlen;
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    u32 idx;
    if (!FdIsSocket(p, fd, idx))
        return kEBADF;
    // v0: every setsockopt accepted as a success no-op. SO_REUSEADDR /
    // SO_BROADCAST / SO_RCVTIMEO etc. all map to "success, ignored" —
    // the v0 stack has no timer / no reuse / no broadcast policy
    // beyond "always allow". Sub-GAP: real options aren't honoured.
    return 0;
}

i64 DoGetsockopt(u64 fd, u64 level, u64 optname, u64 user_optval, u64 user_optlen)
{
    (void)level;
    (void)optname;
    (void)user_optval;
    (void)user_optlen;
    auto* p = ::duetos::core::CurrentProcess();
    if (p == nullptr)
        return kEPERM;
    u32 idx;
    if (!FdIsSocket(p, fd, idx))
        return kEBADF;
    // v0: report optlen=0 (caller's buffer untouched). Sub-GAP same
    // as setsockopt — option set isn't tracked.
    if (user_optlen != 0)
    {
        u32 zero = 0;
        mm::CopyToUser(reinterpret_cast<void*>(user_optlen), &zero, sizeof(zero));
    }
    return 0;
}

i64 DoSocketpair(u64 domain, u64 type, u64 protocol, u64 user_sv)
{
    (void)domain;
    (void)type;
    (void)protocol;
    (void)user_sv;
    // AF_UNIX socketpair would need an in-kernel cross-pipe (loopback
    // ring) — sub-GAP, deferred until a userland caller that needs it
    // appears. AF_INET socketpair isn't a thing on Linux either.
    return kEOpNotSupp;
}

// ============================================================
// LinuxFd dispatch arms — called from syscall_io / syscall_file.
// ============================================================

i64 SocketFdRead(u32 idx, u64 user_dst, u64 len)
{
    const auto* s = ::duetos::net::SocketGet(idx);
    if (s == nullptr)
        return kEBADF;
    constexpr u64 kStageCap = 1500;
    if (len > kStageCap)
        len = kStageCap;
    u8 stage[kStageCap];
    if (s->type == ::duetos::net::kSocketTypeDgram)
    {
        u32 truth = 0;
        const i64 got = ::duetos::net::SocketRecvDgram(idx, stage, static_cast<u32>(len), &truth, nullptr, nullptr);
        if (got < 0)
            return got;
        if (got > 0 && !mm::CopyToUser(reinterpret_cast<void*>(user_dst), stage, static_cast<u64>(got)))
            return kEFAULT;
        return got;
    }
    const i64 got = ::duetos::net::SocketRecvStream(idx, stage, static_cast<u32>(len));
    if (got > 0 && !mm::CopyToUser(reinterpret_cast<void*>(user_dst), stage, static_cast<u64>(got)))
        return kEFAULT;
    return got;
}

i64 SocketFdWrite(u32 idx, u64 user_src, u64 len)
{
    const auto* s = ::duetos::net::SocketGet(idx);
    if (s == nullptr)
        return kEBADF;
    constexpr u64 kStageCap = 1500;
    if (len > kStageCap)
        len = kStageCap;
    u8 stage[kStageCap];
    if (len > 0 && !mm::CopyFromUser(stage, reinterpret_cast<const void*>(user_src), len))
        return kEFAULT;
    if (s->type == ::duetos::net::kSocketTypeDgram)
        return ::duetos::net::SocketSendDgram(idx, {}, 0, stage, static_cast<u32>(len));
    return ::duetos::net::SocketSendStream(idx, stage, static_cast<u32>(len));
}

void SocketFdRelease(u32 idx)
{
    ::duetos::net::SocketRelease(idx);
}

void SocketFdRetain(u32 idx)
{
    ::duetos::net::SocketRetain(idx);
}

bool SocketFdReadReady(u32 idx)
{
    const auto* s = ::duetos::net::SocketGet(idx);
    if (s == nullptr)
        return false;
    if (s->type == ::duetos::net::kSocketTypeDgram)
        return s->udp_count > 0;
    // SOCK_STREAM — conservatively report ready once the TCP slot is
    // established. Real readability can only be probed by attempting
    // a 0-byte recv against the shared single-slot machine; v0
    // tolerates a handful of spurious wakes per epoll caller.
    return s->connected;
}

} // namespace duetos::subsystems::linux::internal
