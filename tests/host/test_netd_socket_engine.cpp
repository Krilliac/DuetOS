// Hosted hostile-state coverage for netd's allocation-free socket coordinator.

#include "host_test_helper.h"
#include "socket_engine.h"
#include "socket_engine_internal.h"

#include <cstdint>
#include <cstring>
#include <limits>

namespace
{

NetdSocketEngine g_engines[17]{};

NetdSocketEngineInstanceIdentity Instance(std::uint64_t generation = 7)
{
    return NetdSocketEngineInstanceIdentity{0x4e45544400000001ULL, generation, {0x50524f4300000001ULL, 500},
                                            0x45504f4348000001ULL, 4,          0};
}

NetdSocketEngineTransportIdentity Transport(std::uint64_t generation = 9)
{
    return NetdSocketEngineTransportIdentity{0x5452414e53500001ULL, generation};
}

NetdSocketEnginePeerIdentity Peer(std::uint64_t seed)
{
    NetdSocketEnginePeerIdentity peer{};
    peer.process = {0x9000000000000000ULL | seed, 1000 + seed};
    peer.credential = {static_cast<std::uint32_t>(seed % NETD_SOCKET_ENGINE_CREDENTIAL_CAPACITY), 0,
                       0x100000000ULL | seed};
    peer.channel = {static_cast<std::uint32_t>(seed % NETD_SOCKET_ENGINE_CHANNEL_CAPACITY),
                    NETD_SOCKET_ENGINE_CHANNEL_ACCEPTOR,
                    {0, 0, 0},
                    0x200000000ULL | seed,
                    0x300000000ULL | seed};
    return peer;
}

NetdSocketEnginePeerAuthority Authority(std::uint64_t seed,
                                        std::uint64_t methods = NETD_SOCKET_ENGINE_METHOD_KNOWN_MASK,
                                        std::uint32_t socket_limit = NETD_SOCKET_ENGINE_MAX_SOCKETS,
                                        std::uint32_t request_limit = NETD_SOCKET_ENGINE_MAX_REQUESTS)
{
    return NetdSocketEnginePeerAuthority{0x400000000ULL | seed, 0x500000000ULL | seed, methods,
                                         socket_limit,          request_limit,         0};
}

NetdSocketEngineTransportReceipt InitializeReady(NetdSocketEngine& engine, std::uint64_t first_generation = 1,
                                                 std::uint64_t transport_generation = 9)
{
    const auto instance = Instance();
    const auto transport = Transport(transport_generation);
    NetdSocketEngineTransportReceipt receipt{};
    EXPECT_EQ(NetdSocketEngineInitialize(&engine, &instance, first_generation), NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(NetdSocketEngineAttachTransport(&engine, &transport, &receipt), NETD_SOCKET_ENGINE_OK);
    return receipt;
}

NetdSocketEnginePeerReceipt OpenPeer(NetdSocketEngine& engine, std::uint64_t seed, std::uint64_t first_request_id = 1,
                                     NetdSocketEnginePeerAuthority authority = Authority(1))
{
    const auto peer = Peer(seed);
    NetdSocketEnginePeerReceipt receipt{};
    EXPECT_EQ(NetdSocketEngineOpenPeer(&engine, &peer, &authority, first_request_id, &receipt), NETD_SOCKET_ENGINE_OK);
    return receipt;
}

NetdSocketEngineRequestReceipt SubmitOpen(NetdSocketEngine& engine, const NetdSocketEnginePeerReceipt& peer,
                                          std::uint64_t request_id)
{
    NetdSocketEngineRequestReceipt receipt{};
    EXPECT_EQ(NetdSocketEngineSubmitOpen(&engine, &peer, request_id, NETD_SOCKET_ENGINE_DOMAIN_IPV4,
                                         NETD_SOCKET_ENGINE_TYPE_STREAM, NETD_SOCKET_ENGINE_PROTOCOL_TCP, 0, &receipt),
              NETD_SOCKET_ENGINE_OK);
    return receipt;
}

NetdSocketEngineWorkItem Claim(NetdSocketEngine& engine)
{
    NetdSocketEngineWorkItem work{};
    EXPECT_EQ(NetdSocketEngineClaimNext(&engine, &work), NETD_SOCKET_ENGINE_OK);
    return work;
}

NetdSocketEngineCompletion OpenSuccess(const NetdSocketEngineTransportIdentity& transport, std::uint64_t identity)
{
    NetdSocketEngineCompletion completion{};
    completion.reply_status = NETD_SOCKET_ENGINE_REPLY_SUCCESS;
    completion.backend = {transport, identity};
    return completion;
}

NetdSocketEngineCompletion Failure(std::uint32_t status = NETD_SOCKET_ENGINE_REPLY_BACKEND_FAILURE)
{
    NetdSocketEngineCompletion completion{};
    completion.reply_status = status;
    return completion;
}

NetdSocketEngineReplyPublication NextReply(NetdSocketEngine& engine)
{
    NetdSocketEngineReplyPublication reply{};
    EXPECT_EQ(NetdSocketEngineGetNextReply(&engine, &reply), NETD_SOCKET_ENGINE_OK);
    return reply;
}

NetdSocketEngineSocketRef OpenSocket(NetdSocketEngine& engine, const NetdSocketEnginePeerReceipt& peer,
                                     std::uint64_t request_id, std::uint64_t backend_identity)
{
    SubmitOpen(engine, peer, request_id);
    const auto work = Claim(engine);
    const auto completion = OpenSuccess(Transport(), backend_identity);
    const auto result = NetdSocketEngineComplete(&engine, &work.lease, &completion);
    EXPECT_EQ(result.status, NETD_SOCKET_ENGINE_OK);
    EXPECT_TRUE(result.reply_ready);
    const auto reply = NextReply(engine);
    EXPECT_EQ(reply.reply.status, static_cast<std::uint32_t>(NETD_SOCKET_ENGINE_REPLY_SUCCESS));
    const auto socket = reply.reply.socket;
    EXPECT_EQ(NetdSocketEngineCommitReply(&engine, &reply.lease), NETD_SOCKET_ENGINE_OK);
    return socket;
}

void TestInitializationAndFailClosedTransport()
{
    const auto instance = Instance();
    const auto peer = Peer(1);
    const auto authority = Authority(1);
    NetdSocketEnginePeerReceipt peer_receipt{};
    NetdSocketEngineSnapshot snapshot{};
    EXPECT_TRUE(NetdSocketEngineInstanceIdentityIsCanonical(&instance));
    EXPECT_TRUE(NetdSocketEnginePeerIdentityIsCanonical(&peer));
    EXPECT_TRUE(NetdSocketEnginePeerAuthorityIsCanonical(&authority));
    EXPECT_EQ(NetdSocketEngineInitialize(&g_engines[0], &instance, 1), NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(NetdSocketEngineDescribe(&g_engines[0], &snapshot), NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(snapshot.state, static_cast<std::uint32_t>(NETD_SOCKET_ENGINE_STATE_AWAITING_TRANSPORT));
    EXPECT_EQ(NetdSocketEngineOpenPeer(&g_engines[0], &peer, &authority, 1, &peer_receipt),
              NETD_SOCKET_ENGINE_TRANSPORT_UNAVAILABLE);

    const auto transport = Transport();
    NetdSocketEngineTransportReceipt transport_receipt{};
    EXPECT_EQ(NetdSocketEngineAttachTransport(&g_engines[0], &transport, &transport_receipt), NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(NetdSocketEngineAttachTransport(&g_engines[0], &transport, &transport_receipt),
              NETD_SOCKET_ENGINE_TRANSPORT_ALREADY_ATTACHED);
    EXPECT_EQ(NetdSocketEngineOpenPeer(&g_engines[0], &peer, &authority, 1, &peer_receipt), NETD_SOCKET_ENGINE_OK);

    union TransportAlias
    {
        NetdSocketEngineTransportIdentity transport;
        NetdSocketEngineTransportReceipt receipt;
    } transport_alias{};
    transport_alias.transport = transport;
    EXPECT_EQ(NetdSocketEngineAttachTransport(&g_engines[0], &transport_alias.transport, &transport_alias.receipt),
              NETD_SOCKET_ENGINE_ALIASED_STORAGE);
    union PeerAlias
    {
        NetdSocketEnginePeerIdentity peer;
        NetdSocketEnginePeerReceipt receipt;
    } peer_alias{};
    peer_alias.peer = Peer(3);
    const auto peer_alias_authority = Authority(3);
    EXPECT_EQ(NetdSocketEngineOpenPeer(&g_engines[0], &peer_alias.peer, &peer_alias_authority, 1, &peer_alias.receipt),
              NETD_SOCKET_ENGINE_ALIASED_STORAGE);

    auto invalid_peer = Peer(2);
    invalid_peer.channel.role = NETD_SOCKET_ENGINE_CHANNEL_INITIATOR;
    EXPECT_FALSE(NetdSocketEnginePeerIdentityIsCanonical(&invalid_peer));
    auto invalid_authority = authority;
    invalid_authority.allowed_methods |= UINT64_C(0x80);
    EXPECT_FALSE(NetdSocketEnginePeerAuthorityIsCanonical(&invalid_authority));
    g_engines[1].bytes[0] = 1;
    EXPECT_EQ(NetdSocketEngineInitialize(&g_engines[1], &instance, 1), NETD_SOCKET_ENGINE_NONZERO_STORAGE);
    EXPECT_EQ(NetdSocketEngineInitialize(
                  &g_engines[2], reinterpret_cast<const NetdSocketEngineInstanceIdentity*>(g_engines[2].bytes), 1),
              NETD_SOCKET_ENGINE_ALIASED_STORAGE);
    EXPECT_STREQ(NetdSocketEngineStatusName(NETD_SOCKET_ENGINE_STALE_TRANSPORT), "stale-transport");
    // 63 is inside the unfixed C enum's value range (38 enumerators -> [0,63])
    // but is not an enumerator; larger probes like 0x7fff are outside the
    // range and the conversion is unspecified (-Werror=conversion under GCC).
    EXPECT_STREQ(NetdSocketEngineStatusName(static_cast<NetdSocketEngineStatus>(63)), "unknown");
}

void TestExactPeerIdentityRightsAndQuota()
{
    InitializeReady(g_engines[3]);
    const auto identity = Peer(10);
    const auto authority = Authority(10);
    NetdSocketEnginePeerReceipt peer{};
    NetdSocketEnginePeerReceipt duplicate{};
    EXPECT_EQ(NetdSocketEngineOpenPeer(&g_engines[3], &identity, &authority, 1, &peer), NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(NetdSocketEngineOpenPeer(&g_engines[3], &identity, &authority, 1, &duplicate),
              NETD_SOCKET_ENGINE_PEER_EXISTS);

    NetdSocketEngineRequestReceipt request{};
    auto splice = peer;
    ++splice.peer.process.identity;
    EXPECT_EQ(NetdSocketEngineSubmitOpen(&g_engines[3], &splice, 1, NETD_SOCKET_ENGINE_DOMAIN_IPV4,
                                         NETD_SOCKET_ENGINE_TYPE_STREAM, NETD_SOCKET_ENGINE_PROTOCOL_TCP, 0, &request),
              NETD_SOCKET_ENGINE_STALE_PEER);
    splice = peer;
    ++splice.peer.credential.generation;
    EXPECT_EQ(NetdSocketEngineSubmitOpen(&g_engines[3], &splice, 1, NETD_SOCKET_ENGINE_DOMAIN_IPV4,
                                         NETD_SOCKET_ENGINE_TYPE_STREAM, NETD_SOCKET_ENGINE_PROTOCOL_TCP, 0, &request),
              NETD_SOCKET_ENGINE_STALE_PEER);
    splice = peer;
    ++splice.peer.channel.generation;
    EXPECT_EQ(NetdSocketEngineSubmitOpen(&g_engines[3], &splice, 1, NETD_SOCKET_ENGINE_DOMAIN_IPV4,
                                         NETD_SOCKET_ENGINE_TYPE_STREAM, NETD_SOCKET_ENGINE_PROTOCOL_TCP, 0, &request),
              NETD_SOCKET_ENGINE_STALE_PEER);
    auto colliding_identity = Peer(99);
    colliding_identity.channel = identity.channel;
    const auto colliding_authority = Authority(99);
    EXPECT_EQ(NetdSocketEngineOpenPeer(&g_engines[3], &colliding_identity, &colliding_authority, 1, &splice),
              NETD_SOCKET_ENGINE_INVALID_IDENTITY);

    const auto open_only_authority = Authority(11, NETD_SOCKET_ENGINE_METHOD_OPEN, 1, 4);
    const auto open_only = OpenPeer(g_engines[3], 11, 1, open_only_authority);
    const auto socket = OpenSocket(g_engines[3], open_only, 1, 0x101);
    EXPECT_EQ(NetdSocketEngineSubmitClose(&g_engines[3], &open_only, 2, &socket, &request),
              NETD_SOCKET_ENGINE_UNAUTHORIZED);

    const auto quota_authority = Authority(12, NETD_SOCKET_ENGINE_METHOD_KNOWN_MASK, 1, 4);
    const auto quota_peer = OpenPeer(g_engines[3], 12, 1, quota_authority);
    SubmitOpen(g_engines[3], quota_peer, 1);
    EXPECT_EQ(NetdSocketEngineSubmitOpen(&g_engines[3], &quota_peer, 2, NETD_SOCKET_ENGINE_DOMAIN_IPV4,
                                         NETD_SOCKET_ENGINE_TYPE_STREAM, NETD_SOCKET_ENGINE_PROTOCOL_TCP, 0, &request),
              NETD_SOCKET_ENGINE_SOCKET_CAPACITY);
    const auto cancelled = NetdSocketEngineCancel(&g_engines[3], &quota_peer, 1);
    EXPECT_EQ(cancelled.status, NETD_SOCKET_ENGINE_OK);
    EXPECT_TRUE(cancelled.reply_ready);
    const auto reply = NextReply(g_engines[3]);
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[3], &reply.lease), NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(NetdSocketEngineSubmitOpen(&g_engines[3], &quota_peer, 2, NETD_SOCKET_ENGINE_DOMAIN_IPV4,
                                         NETD_SOCKET_ENGINE_TYPE_STREAM, NETD_SOCKET_ENGINE_PROTOCOL_TCP, 0, &request),
              NETD_SOCKET_ENGINE_OK);
}

void TestOpenCloseReplyTransaction()
{
    InitializeReady(g_engines[4]);
    const auto peer = OpenPeer(g_engines[4], 20);
    const auto request = SubmitOpen(g_engines[4], peer, 1);
    NetdSocketEngineRequestReceipt rejected{};
    EXPECT_EQ(NetdSocketEngineSubmitOpen(&g_engines[4], &peer, 1, NETD_SOCKET_ENGINE_DOMAIN_IPV4,
                                         NETD_SOCKET_ENGINE_TYPE_STREAM, NETD_SOCKET_ENGINE_PROTOCOL_TCP, 0, &rejected),
              NETD_SOCKET_ENGINE_REPLAYED_REQUEST);
    EXPECT_EQ(NetdSocketEngineSubmitOpen(&g_engines[4], &peer, 3, NETD_SOCKET_ENGINE_DOMAIN_IPV4,
                                         NETD_SOCKET_ENGINE_TYPE_STREAM, NETD_SOCKET_ENGINE_PROTOCOL_TCP, 0, &rejected),
              NETD_SOCKET_ENGINE_OUT_OF_ORDER_REQUEST);
    NetdSocketEngineRequestSnapshot request_snapshot{};
    EXPECT_EQ(NetdSocketEngineInspectRequest(&g_engines[4], &request, &request_snapshot), NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(request_snapshot.phase, static_cast<std::uint32_t>(NETD_SOCKET_ENGINE_REQUEST_QUEUED));

    const auto work = Claim(g_engines[4]);
    auto wrong_transport = OpenSuccess(Transport(10), 0x201);
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[4], &work.lease, &wrong_transport).status,
              NETD_SOCKET_ENGINE_INVALID_COMPLETION);
    const auto success = OpenSuccess(Transport(), 0x201);
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[4], &work.lease, &success).status, NETD_SOCKET_ENGINE_OK);
    auto reply = NextReply(g_engines[4]);
    const auto socket = reply.reply.socket;
    EXPECT_EQ(NetdSocketEngineSubmitOpen(&g_engines[4], &peer, 2, NETD_SOCKET_ENGINE_DOMAIN_IPV4,
                                         NETD_SOCKET_ENGINE_TYPE_STREAM, NETD_SOCKET_ENGINE_PROTOCOL_TCP, 0, &rejected),
              NETD_SOCKET_ENGINE_REPLY_IN_FLIGHT);
    EXPECT_EQ(NetdSocketEngineAbortReply(&g_engines[4], &reply.lease), NETD_SOCKET_ENGINE_OK);
    reply = NextReply(g_engines[4]);
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[4], &reply.lease), NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[4], &reply.lease), NETD_SOCKET_ENGINE_STALE_WORK);

    EXPECT_EQ(NetdSocketEngineSubmitClose(&g_engines[4], &peer, 2, &socket, &rejected), NETD_SOCKET_ENGINE_OK);
    auto close_work = Claim(g_engines[4]);
    EXPECT_EQ(close_work.backend.identity, UINT64_C(0x201));
    const auto close_failure = Failure();
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[4], &close_work.lease, &close_failure).status, NETD_SOCKET_ENGINE_OK);
    reply = NextReply(g_engines[4]);
    EXPECT_EQ(reply.reply.status, static_cast<std::uint32_t>(NETD_SOCKET_ENGINE_REPLY_BACKEND_FAILURE));
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[4], &reply.lease), NETD_SOCKET_ENGINE_OK);
    NetdSocketEngineSocketSnapshot socket_snapshot{};
    EXPECT_EQ(NetdSocketEngineInspectSocket(&g_engines[4], &peer, &socket, &socket_snapshot), NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(socket_snapshot.phase, static_cast<std::uint32_t>(NETD_SOCKET_ENGINE_SOCKET_LIVE));

    EXPECT_EQ(NetdSocketEngineSubmitClose(&g_engines[4], &peer, 3, &socket, &rejected), NETD_SOCKET_ENGINE_OK);
    close_work = Claim(g_engines[4]);
    const auto close_success = Failure(NETD_SOCKET_ENGINE_REPLY_SUCCESS);
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[4], &close_work.lease, &close_success).status, NETD_SOCKET_ENGINE_OK);
    reply = NextReply(g_engines[4]);
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[4], &reply.lease), NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(NetdSocketEngineInspectSocket(&g_engines[4], &peer, &socket, &socket_snapshot),
              NETD_SOCKET_ENGINE_STALE_SOCKET);
}

void TestCancellationLinearization()
{
    InitializeReady(g_engines[5]);
    const auto peer = OpenPeer(g_engines[5], 30);

    SubmitOpen(g_engines[5], peer, 1);
    auto cancel = NetdSocketEngineCancel(&g_engines[5], &peer, 1);
    EXPECT_EQ(cancel.status, NETD_SOCKET_ENGINE_OK);
    EXPECT_TRUE(cancel.reply_ready);
    EXPECT_FALSE(cancel.cleanup_valid);
    auto reply = NextReply(g_engines[5]);
    EXPECT_EQ(reply.reply.status, static_cast<std::uint32_t>(NETD_SOCKET_ENGINE_REPLY_CANCELLED));
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[5], &reply.lease), NETD_SOCKET_ENGINE_OK);

    SubmitOpen(g_engines[5], peer, 2);
    auto work = Claim(g_engines[5]);
    cancel = NetdSocketEngineCancel(&g_engines[5], &peer, 2);
    EXPECT_EQ(cancel.status, NETD_SOCKET_ENGINE_OK);
    union CancellationAlias
    {
        NetdSocketEngineWorkLease lease;
        std::uint8_t cancellation;
    } cancellation_alias{};
    cancellation_alias.lease = work.lease;
    EXPECT_EQ(
        NetdSocketEngineCheckCancellation(&g_engines[5], &cancellation_alias.lease, &cancellation_alias.cancellation),
        NETD_SOCKET_ENGINE_ALIASED_STORAGE);
    std::uint8_t cancellation = 0;
    EXPECT_EQ(NetdSocketEngineCheckCancellation(&g_engines[5], &work.lease, &cancellation), NETD_SOCKET_ENGINE_OK);
    EXPECT_TRUE(cancellation);
    auto completion = OpenSuccess(Transport(), 0x301);
    auto completed = NetdSocketEngineComplete(&g_engines[5], &work.lease, &completion);
    EXPECT_EQ(completed.status, NETD_SOCKET_ENGINE_OK);
    EXPECT_TRUE(completed.cleanup_valid);
    EXPECT_EQ(completed.cleanup.reason, static_cast<std::uint32_t>(NETD_SOCKET_ENGINE_CLEANUP_CANCELLED_OPEN));
    EXPECT_EQ(completed.cleanup.backend.identity, UINT64_C(0x301));
    reply = NextReply(g_engines[5]);
    EXPECT_EQ(reply.reply.status, static_cast<std::uint32_t>(NETD_SOCKET_ENGINE_REPLY_CANCELLED));
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[5], &reply.lease), NETD_SOCKET_ENGINE_OK);

    SubmitOpen(g_engines[5], peer, 3);
    work = Claim(g_engines[5]);
    completion = OpenSuccess(Transport(), 0x302);
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[5], &work.lease, &completion).status, NETD_SOCKET_ENGINE_OK);
    cancel = NetdSocketEngineCancel(&g_engines[5], &peer, 3);
    EXPECT_EQ(cancel.status, NETD_SOCKET_ENGINE_OK);
    EXPECT_TRUE(cancel.cleanup_valid);
    reply = NextReply(g_engines[5]);
    EXPECT_EQ(NetdSocketEngineCancel(&g_engines[5], &peer, 3).status, NETD_SOCKET_ENGINE_CANCEL_TOO_LATE);
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[5], &reply.lease), NETD_SOCKET_ENGINE_OK);

    const auto socket = OpenSocket(g_engines[5], peer, 4, 0x303);
    NetdSocketEngineRequestReceipt close_receipt{};
    EXPECT_EQ(NetdSocketEngineSubmitClose(&g_engines[5], &peer, 5, &socket, &close_receipt), NETD_SOCKET_ENGINE_OK);
    cancel = NetdSocketEngineCancel(&g_engines[5], &peer, 5);
    EXPECT_EQ(cancel.status, NETD_SOCKET_ENGINE_OK);
    reply = NextReply(g_engines[5]);
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[5], &reply.lease), NETD_SOCKET_ENGINE_OK);
    NetdSocketEngineSocketSnapshot socket_snapshot{};
    EXPECT_EQ(NetdSocketEngineInspectSocket(&g_engines[5], &peer, &socket, &socket_snapshot), NETD_SOCKET_ENGINE_OK);

    EXPECT_EQ(NetdSocketEngineSubmitClose(&g_engines[5], &peer, 6, &socket, &close_receipt), NETD_SOCKET_ENGINE_OK);
    work = Claim(g_engines[5]);
    EXPECT_EQ(NetdSocketEngineCancel(&g_engines[5], &peer, 6).status, NETD_SOCKET_ENGINE_CANCEL_TOO_LATE);
    const auto close_success = Failure(NETD_SOCKET_ENGINE_REPLY_SUCCESS);
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[5], &work.lease, &close_success).status, NETD_SOCKET_ENGINE_OK);
    reply = NextReply(g_engines[5]);
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[5], &reply.lease), NETD_SOCKET_ENGINE_OK);
}

void TestPeerCloseCleansEveryOwnershipPhase()
{
    InitializeReady(g_engines[6]);
    const auto peer_a = OpenPeer(g_engines[6], 40);
    const auto peer_b = OpenPeer(g_engines[6], 41);
    OpenSocket(g_engines[6], peer_a, 1, 0x401);

    SubmitOpen(g_engines[6], peer_a, 2);
    const auto running = Claim(g_engines[6]);
    SubmitOpen(g_engines[6], peer_a, 3);
    const auto ready_work = Claim(g_engines[6]);
    const auto ready_completion = OpenSuccess(Transport(), 0x403);
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[6], &ready_work.lease, &ready_completion).status,
              NETD_SOCKET_ENGINE_OK);
    SubmitOpen(g_engines[6], peer_a, 4);

    NetdSocketEngineCleanupBatch cleanup{};
    EXPECT_EQ(NetdSocketEngineClosePeer(&g_engines[6], &peer_a, &cleanup), NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(cleanup.count, 2U);
    NetdSocketEngineRequestReceipt request{};
    EXPECT_EQ(NetdSocketEngineSubmitOpen(&g_engines[6], &peer_a, 5, NETD_SOCKET_ENGINE_DOMAIN_IPV4,
                                         NETD_SOCKET_ENGINE_TYPE_STREAM, NETD_SOCKET_ENGINE_PROTOCOL_TCP, 0, &request),
              NETD_SOCKET_ENGINE_PEER_CLOSING);
    const auto running_completion = OpenSuccess(Transport(), 0x402);
    const auto completed = NetdSocketEngineComplete(&g_engines[6], &running.lease, &running_completion);
    EXPECT_EQ(completed.status, NETD_SOCKET_ENGINE_OK);
    EXPECT_TRUE(completed.cleanup_valid);
    EXPECT_TRUE(completed.request_retired);
    EXPECT_EQ(completed.cleanup.reason, static_cast<std::uint32_t>(NETD_SOCKET_ENGINE_CLEANUP_PEER_CLOSED));
    EXPECT_EQ(NetdSocketEngineClosePeer(&g_engines[6], &peer_a, &cleanup), NETD_SOCKET_ENGINE_STALE_PEER);
    EXPECT_EQ(NetdSocketEngineSubmitOpen(&g_engines[6], &peer_b, 1, NETD_SOCKET_ENGINE_DOMAIN_IPV4,
                                         NETD_SOCKET_ENGINE_TYPE_DATAGRAM, NETD_SOCKET_ENGINE_PROTOCOL_UDP, 0,
                                         &request),
              NETD_SOCKET_ENGINE_OK);
}

void TestTransportDrainWaitsForPinnedWork()
{
    const auto transport_receipt = InitializeReady(g_engines[7]);
    const auto peer = OpenPeer(g_engines[7], 50);
    (void)OpenSocket(g_engines[7], peer, 1, 0x501);

    SubmitOpen(g_engines[7], peer, 2);
    const auto running = Claim(g_engines[7]);
    SubmitOpen(g_engines[7], peer, 3);
    const auto ready_work = Claim(g_engines[7]);
    const auto ready_completion = OpenSuccess(Transport(), 0x503);
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[7], &ready_work.lease, &ready_completion).status,
              NETD_SOCKET_ENGINE_OK);

    auto reply = NextReply(g_engines[7]);
    NetdSocketEngineCleanupBatch cleanup{};
    EXPECT_EQ(NetdSocketEngineBeginDrain(&g_engines[7], &transport_receipt, &cleanup),
              NETD_SOCKET_ENGINE_REPLY_IN_FLIGHT);
    EXPECT_EQ(NetdSocketEngineAbortReply(&g_engines[7], &reply.lease), NETD_SOCKET_ENGINE_OK);

    auto stale_transport = transport_receipt;
    ++stale_transport.transport.generation;
    EXPECT_EQ(NetdSocketEngineBeginDrain(&g_engines[7], &stale_transport, &cleanup),
              NETD_SOCKET_ENGINE_STALE_TRANSPORT);
    EXPECT_EQ(cleanup.count, 0U);
    EXPECT_EQ(NetdSocketEngineBeginDrain(&g_engines[7], &transport_receipt, &cleanup), NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(cleanup.count, 2U);
    EXPECT_EQ(NetdSocketEngineFinishDrain(&g_engines[7]), NETD_SOCKET_ENGINE_BUSY);

    std::uint8_t cancellation = 0;
    EXPECT_EQ(NetdSocketEngineCheckCancellation(&g_engines[7], &running.lease, &cancellation), NETD_SOCKET_ENGINE_OK);
    EXPECT_TRUE(cancellation);
    const auto running_completion = OpenSuccess(Transport(), 0x502);
    const auto completed = NetdSocketEngineComplete(&g_engines[7], &running.lease, &running_completion);
    EXPECT_EQ(completed.status, NETD_SOCKET_ENGINE_OK);
    EXPECT_TRUE(completed.cleanup_valid);
    EXPECT_TRUE(completed.request_retired);
    EXPECT_EQ(completed.cleanup.reason, static_cast<std::uint32_t>(NETD_SOCKET_ENGINE_CLEANUP_TRANSPORT_DRAIN));
    EXPECT_EQ(completed.cleanup.backend.identity, UINT64_C(0x502));
    EXPECT_EQ(NetdSocketEngineFinishDrain(&g_engines[7]), NETD_SOCKET_ENGINE_OK);

    NetdSocketEngineSnapshot snapshot{};
    EXPECT_EQ(NetdSocketEngineDescribe(&g_engines[7], &snapshot), NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(snapshot.state, static_cast<std::uint32_t>(NETD_SOCKET_ENGINE_STATE_CLOSED));
    EXPECT_EQ(snapshot.peer_count, 0U);
    EXPECT_EQ(snapshot.socket_count, 0U);
    EXPECT_EQ(snapshot.request_count, 0U);
    EXPECT_EQ(snapshot.transport.identity, UINT64_C(0));
    EXPECT_EQ(NetdSocketEngineSubmitOpen(&g_engines[7], &peer, 4, NETD_SOCKET_ENGINE_DOMAIN_IPV4,
                                         NETD_SOCKET_ENGINE_TYPE_STREAM, NETD_SOCKET_ENGINE_PROTOCOL_TCP, 0,
                                         &reply.lease.request),
              NETD_SOCKET_ENGINE_CLOSED);

    const auto instance = Instance(8);
    EXPECT_EQ(NetdSocketEngineInitialize(&g_engines[8], &instance, 1), NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(NetdSocketEngineBeginDrain(&g_engines[8], nullptr, &cleanup), NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(NetdSocketEngineFinishDrain(&g_engines[8]), NETD_SOCKET_ENGINE_OK);
}

void TestSequenceAndGenerationExhaustion()
{
    InitializeReady(g_engines[9]);
    const auto sequence_peer = OpenPeer(g_engines[9], 60, UINT64_MAX);
    SubmitOpen(g_engines[9], sequence_peer, UINT64_MAX);
    auto cancelled = NetdSocketEngineCancel(&g_engines[9], &sequence_peer, UINT64_MAX);
    EXPECT_EQ(cancelled.status, NETD_SOCKET_ENGINE_OK);
    auto reply = NextReply(g_engines[9]);
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[9], &reply.lease), NETD_SOCKET_ENGINE_OK);
    NetdSocketEngineRequestReceipt request{};
    EXPECT_EQ(NetdSocketEngineSubmitOpen(&g_engines[9], &sequence_peer, 1, NETD_SOCKET_ENGINE_DOMAIN_IPV4,
                                         NETD_SOCKET_ENGINE_TYPE_STREAM, NETD_SOCKET_ENGINE_PROTOCOL_TCP, 0, &request),
              NETD_SOCKET_ENGINE_SEQUENCE_EXHAUSTED);

    InitializeReady(g_engines[10], UINT64_MAX);
    const auto slot_peer = OpenPeer(g_engines[10], 70);
    for (std::uint64_t request_id = 1; request_id <= NETD_SOCKET_ENGINE_MAX_REQUESTS; ++request_id)
    {
        SubmitOpen(g_engines[10], slot_peer, request_id);
        const auto work = Claim(g_engines[10]);
        const auto failure = Failure();
        EXPECT_EQ(NetdSocketEngineComplete(&g_engines[10], &work.lease, &failure).status, NETD_SOCKET_ENGINE_OK);
        reply = NextReply(g_engines[10]);
        EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[10], &reply.lease), NETD_SOCKET_ENGINE_OK);
    }
    EXPECT_EQ(NetdSocketEngineSubmitOpen(&g_engines[10], &slot_peer, 65, NETD_SOCKET_ENGINE_DOMAIN_IPV4,
                                         NETD_SOCKET_ENGINE_TYPE_STREAM, NETD_SOCKET_ENGINE_PROTOCOL_TCP, 0, &request),
              NETD_SOCKET_ENGINE_GENERATION_EXHAUSTED);

    InitializeReady(g_engines[11], UINT64_MAX);
    NetdSocketEngineCleanupBatch cleanup{};
    for (std::uint64_t seed = 100; seed < 100 + NETD_SOCKET_ENGINE_MAX_PEERS; ++seed)
    {
        const auto retired_peer = OpenPeer(g_engines[11], seed);
        EXPECT_EQ(NetdSocketEngineClosePeer(&g_engines[11], &retired_peer, &cleanup), NETD_SOCKET_ENGINE_OK);
        EXPECT_EQ(cleanup.count, 0U);
    }
    const auto extra_identity = Peer(200);
    const auto authority = Authority(200);
    NetdSocketEnginePeerReceipt extra_peer{};
    EXPECT_EQ(NetdSocketEngineOpenPeer(&g_engines[11], &extra_identity, &authority, 1, &extra_peer),
              NETD_SOCKET_ENGINE_GENERATION_EXHAUSTED);
}

void TestDeferredSocketReferenceStaysPinned()
{
    InitializeReady(g_engines[12]);
    const auto peer = OpenPeer(g_engines[12], 80);
    const auto request = SubmitOpen(g_engines[12], peer, 1);
    const auto work = Claim(g_engines[12]);
    auto completion = OpenSuccess(Transport(), 0x801);
    completion.reserved32 = 1;
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[12], &work.lease, &completion).status,
              NETD_SOCKET_ENGINE_INVALID_COMPLETION);
    completion.reserved32 = 0;
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[12], &work.lease, &completion).status, NETD_SOCKET_ENGINE_OK);

    NetdSocketEngineRequestSnapshot snapshot{};
    EXPECT_EQ(NetdSocketEngineInspectRequest(&g_engines[12], &request, &snapshot), NETD_SOCKET_ENGINE_OK);
    const auto predicted_socket = snapshot.request.socket;
    NetdSocketEngineRequestReceipt close{};
    EXPECT_EQ(NetdSocketEngineSubmitClose(&g_engines[12], &peer, 2, &predicted_socket, &close),
              NETD_SOCKET_ENGINE_SOCKET_BUSY);
    auto reply = NextReply(g_engines[12]);
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[12], &reply.lease), NETD_SOCKET_ENGINE_OK);

    EXPECT_EQ(NetdSocketEngineSubmitClose(&g_engines[12], &peer, 2, &predicted_socket, &close), NETD_SOCKET_ENGINE_OK);
    const auto cancelled = NetdSocketEngineCancel(&g_engines[12], &peer, 2);
    EXPECT_EQ(cancelled.status, NETD_SOCKET_ENGINE_OK);
    EXPECT_TRUE(cancelled.reply_ready);
    EXPECT_EQ(NetdSocketEngineSubmitClose(&g_engines[12], &peer, 3, &predicted_socket, &close),
              NETD_SOCKET_ENGINE_SOCKET_BUSY);
    reply = NextReply(g_engines[12]);
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[12], &reply.lease), NETD_SOCKET_ENGINE_OK);

    EXPECT_EQ(NetdSocketEngineSubmitClose(&g_engines[12], &peer, 3, &predicted_socket, &close), NETD_SOCKET_ENGINE_OK);
    const auto close_work = Claim(g_engines[12]);
    const auto close_success = Failure(NETD_SOCKET_ENGINE_REPLY_SUCCESS);
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[12], &close_work.lease, &close_success).status,
              NETD_SOCKET_ENGINE_OK);
    reply = NextReply(g_engines[12]);
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[12], &reply.lease), NETD_SOCKET_ENGINE_OK);
}

void TestCorruptInternalStateFailsClosed()
{
    InitializeReady(g_engines[13]);
    const auto peer = OpenPeer(g_engines[13], 90);
    const auto request = SubmitOpen(g_engines[13], peer, 1);
    const auto work = Claim(g_engines[13]);
    const auto completion = OpenSuccess(Transport(), 0x901);
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[13], &work.lease, &completion).status, NETD_SOCKET_ENGINE_OK);
    auto* implementation = reinterpret_cast<NetdSocketEngineImpl*>(&g_engines[13]);
    implementation->requests[request.request_slot].socket_slot = NETD_SOCKET_ENGINE_INVALID_SLOT;
    EXPECT_EQ(NetdSocketEngineCancel(&g_engines[13], &peer, 1).status, NETD_SOCKET_ENGINE_CORRUPT_STATE);

    InitializeReady(g_engines[14]);
    implementation = reinterpret_cast<NetdSocketEngineImpl*>(&g_engines[14]);
    implementation->sockets[0].reserved32 = 1;
    NetdSocketEngineSnapshot engine_snapshot{};
    EXPECT_EQ(NetdSocketEngineDescribe(&g_engines[14], &engine_snapshot), NETD_SOCKET_ENGINE_CORRUPT_STATE);

    InitializeReady(g_engines[15]);
    const auto publisher_peer = OpenPeer(g_engines[15], 91);
    const auto first = SubmitOpen(g_engines[15], publisher_peer, 1);
    const auto first_work = Claim(g_engines[15]);
    const auto first_completion = OpenSuccess(Transport(), 0x902);
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[15], &first_work.lease, &first_completion).status,
              NETD_SOCKET_ENGINE_OK);
    const auto second = SubmitOpen(g_engines[15], publisher_peer, 2);
    const auto second_work = Claim(g_engines[15]);
    const auto second_completion = OpenSuccess(Transport(), 0x903);
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[15], &second_work.lease, &second_completion).status,
              NETD_SOCKET_ENGINE_OK);
    implementation = reinterpret_cast<NetdSocketEngineImpl*>(&g_engines[15]);
    implementation->requests[first.request_slot].state = NETD_SOCKET_ENGINE_REQUEST_REPLY_PUBLISHING_INTERNAL;
    implementation->requests[second.request_slot].state = NETD_SOCKET_ENGINE_REQUEST_REPLY_PUBLISHING_INTERNAL;
    EXPECT_EQ(NetdSocketEngineDescribe(&g_engines[15], &engine_snapshot), NETD_SOCKET_ENGINE_CORRUPT_STATE);
}

void TestSocketOwnershipAndBackendIdentityAreExact()
{
    InitializeReady(g_engines[16]);
    const auto peer_a = OpenPeer(g_engines[16], 100);
    const auto peer_b = OpenPeer(g_engines[16], 101);
    const auto socket_a = OpenSocket(g_engines[16], peer_a, 1, 0xa01);
    NetdSocketEngineRequestReceipt request{};
    EXPECT_EQ(NetdSocketEngineSubmitClose(&g_engines[16], &peer_b, 1, &socket_a, &request),
              NETD_SOCKET_ENGINE_STALE_SOCKET);

    const auto request_a = SubmitOpen(g_engines[16], peer_a, 2);
    const auto request_b = SubmitOpen(g_engines[16], peer_b, 1);
    (void)request_a;
    (void)request_b;
    const auto work_a = Claim(g_engines[16]);
    const auto work_b = Claim(g_engines[16]);
    const auto backend_a = OpenSuccess(Transport(), 0xa02);
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[16], &work_a.lease, &backend_a).status, NETD_SOCKET_ENGINE_OK);
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[16], &work_b.lease, &backend_a).status,
              NETD_SOCKET_ENGINE_INVALID_COMPLETION);
    const auto backend_b = OpenSuccess(Transport(), 0xa03);
    EXPECT_EQ(NetdSocketEngineComplete(&g_engines[16], &work_b.lease, &backend_b).status, NETD_SOCKET_ENGINE_OK);
    auto reply = NextReply(g_engines[16]);
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[16], &reply.lease), NETD_SOCKET_ENGINE_OK);
    reply = NextReply(g_engines[16]);
    EXPECT_EQ(NetdSocketEngineCommitReply(&g_engines[16], &reply.lease), NETD_SOCKET_ENGINE_OK);
}

} // namespace

int main()
{
    TestInitializationAndFailClosedTransport();
    TestExactPeerIdentityRightsAndQuota();
    TestOpenCloseReplyTransaction();
    TestCancellationLinearization();
    TestPeerCloseCleansEveryOwnershipPhase();
    TestTransportDrainWaitsForPinnedWork();
    TestSequenceAndGenerationExhaustion();
    TestDeferredSocketReferenceStaysPinned();
    TestCorruptInternalStateFailsClosed();
    TestSocketOwnershipAndBackendIdentityAreExact();
    return duetos_host_test::finish_main("netd_socket_engine");
}
