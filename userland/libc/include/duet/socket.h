#pragma once

/*
 * DuetOS — native-libc BSD socket wrappers, v0.
 *
 * Thin header-only typed wrappers over the kernel's multiplexed
 * SYS_SOCKET_OP (see duet/syscall.h). They drive the SAME kernel
 * socket pool that the Win32 ws2_32.dll reaches — one TCP/IP stack,
 * two ABI front-ends (subsystem-isolation rule #6). Every op is
 * cap-gated on kCapNet by the kernel; a process without it gets
 * -EACCES back.
 *
 * v0 scope: AF_INET + SOCK_STREAM, blocking accept/recv (the kernel
 * net layer blocks until a connection / data arrives or the peer
 * FINs — see kernel/net/socket.cpp). Enough for a resident TCP
 * server (see userland/native-apps/netd).
 *
 * Wrappers are `static inline` so a freestanding app linked with
 * `--no-undefined` pulls in only what it calls and adds no new TU to
 * the native-app build.
 */

#include "duet/syscall.h"

#define DUET_AF_INET 2
#define DUET_SOCK_STREAM 1
#define DUET_SOCK_DGRAM 2
#define DUET_INADDR_ANY 0u

/* 16-byte sockaddr_in, byte-for-byte the kernel's LinuxSockaddrIn:
 *   family(2) | port(2, network order) | addr[4] | zero[8].
 * sin_port / sin_addr are stored in network (big-endian) byte order;
 * use duet_htons() / duet_htonl() to fill them. */
struct duet_sockaddr_in
{
    unsigned short sin_family;
    unsigned short sin_port;   /* network order */
    unsigned char sin_addr[4]; /* network order */
    unsigned char sin_zero[8];
};

static inline unsigned short duet_htons(unsigned short x)
{
    return (unsigned short)(((x & 0xFFu) << 8) | ((x >> 8) & 0xFFu));
}

static inline unsigned int duet_htonl(unsigned int x)
{
    return ((x & 0xFFu) << 24) | ((x & 0xFF00u) << 8) | ((x >> 8) & 0xFF00u) | ((x >> 24) & 0xFFu);
}

/* Fill an AF_INET sockaddr for INADDR_ANY:<port>. */
static inline void duet_sockaddr_in_any(struct duet_sockaddr_in* sa, unsigned short port)
{
    sa->sin_family = DUET_AF_INET;
    sa->sin_port = duet_htons(port);
    for (int i = 0; i < 4; ++i)
        sa->sin_addr[i] = 0;
    for (int i = 0; i < 8; ++i)
        sa->sin_zero[i] = 0;
}

/* Returns a kernel socket index (>= 0) or a negative -errno. */
static inline int duet_socket(int domain, int type)
{
    return (int)duet_socket_op(DUET_SOCKOP_CREATE, domain, type, 0, 0, 0);
}

/* addr is a struct duet_sockaddr_in*; len is its byte size (a value,
 * matching the kernel's read_sa). Returns 0 or negative -errno. */
static inline int duet_bind(int s, const struct duet_sockaddr_in* addr, int len)
{
    return (int)duet_socket_op(DUET_SOCKOP_BIND, s, (long)addr, len, 0, 0);
}

static inline int duet_listen(int s, int backlog)
{
    return (int)duet_socket_op(DUET_SOCKOP_LISTEN, s, backlog, 0, 0, 0);
}

/* Blocks until a connection arrives. `addr`/`addrlen` may be NULL when
 * the peer address is not needed (addrlen, when non-NULL, points at an
 * int holding the buffer capacity — BSD/Winsock shape). Returns the
 * accepted socket index (>= 0) or negative -errno. */
static inline int duet_accept(int s, struct duet_sockaddr_in* addr, int* addrlen)
{
    return (int)duet_socket_op(DUET_SOCKOP_ACCEPT, s, (long)addr, (long)addrlen, 0, 0);
}

/* Blocks until data arrives or the peer closes (returns 0 on orderly
 * EOF). Returns bytes read (> 0), 0 on EOF, or negative -errno. */
static inline long duet_recv(int s, void* buf, long len)
{
    return duet_socket_op(DUET_SOCKOP_RECVFROM, s, (long)buf, len, 0, 0);
}

static inline long duet_send(int s, const void* buf, long len)
{
    return duet_socket_op(DUET_SOCKOP_SENDTO, s, (long)buf, len, 0, 0);
}

static inline int duet_sock_close(int s)
{
    return (int)duet_socket_op(DUET_SOCKOP_CLOSE, s, 0, 0, 0, 0);
}
