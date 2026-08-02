// Hosted hostile-state coverage for the allocation-free execd worker engine.

#include "host_test_helper.h"
#include "worker.h"

#include <cstdint>
#include <cstring>
#include <limits>

namespace
{

ExecdWorker g_workers[12]{};

ExecdWorkerInstanceIdentity Instance(std::uint64_t generation = 7)
{
    return ExecdWorkerInstanceIdentity{0x4558454344000001ULL, generation, {0x50524f4300000001ULL, 200},
                                       0x45504f4348000001ULL, 1,          0};
}

ExecdWorkerPeerIdentity Peer(std::uint64_t seed)
{
    return ExecdWorkerPeerIdentity{{0x9000000000000000ULL | seed, 1000 + seed},
                                   {static_cast<std::uint32_t>(seed % 64), 0, 0xA000000000000000ULL | seed},
                                   0xB000000000000000ULL | seed};
}

void FillHash(std::uint8_t hash[32], std::uint8_t seed)
{
    for (std::uint32_t index = 0; index < 32; ++index)
        hash[index] = static_cast<std::uint8_t>(seed + index * 3U);
    hash[0] |= 1U;
}

ExecdWorkerSourceAuthority Source(std::uint64_t seed)
{
    ExecdWorkerSourceAuthority source{};
    source.transfer_reference = 0x40 + seed;
    source.object_identity = 0x100000 + seed;
    source.object_bytes = 4096 + seed;
    source.immutable_policy_id = EXECD_WORKER_SOURCE_POLICY_V1;
    source.sealed = 1;
    source.read_only = 1;
    FillHash(source.source_hash, static_cast<std::uint8_t>(seed));
    return source;
}

ExecdWorkerParseRequest Request(std::uint64_t request_id, std::uint64_t seed,
                                ExecdWorkerFormatHint format = EXECD_WORKER_FORMAT_ELF64)
{
    ExecdWorkerParseRequest request{};
    request.request_id = request_id;
    request.source = Source(seed);
    request.format_hint = static_cast<std::uint16_t>(format);
    return request;
}

ExecdWorkerPlanAuthority Plan(const ExecdWorkerParseRequest& request, std::uint64_t seed)
{
    ExecdWorkerPlanAuthority plan{};
    plan.transfer_reference = 0x400 + seed;
    plan.object_identity = 0x200000 + seed;
    plan.object_bytes = EXECD_WORKER_LOAD_PLAN_MIN_BYTES + 72;
    plan.immutable_policy_id = EXECD_WORKER_LOAD_PLAN_POLICY_V1;
    plan.sealed = 1;
    plan.read_only = 1;
    FillHash(plan.object_hash, static_cast<std::uint8_t>(0x80U + seed));
    std::memcpy(plan.source_hash, request.source.source_hash, sizeof(plan.source_hash));
    return plan;
}

ExecdWorkerCompletion Success(const ExecdWorkerParseRequest& request, std::uint64_t seed)
{
    ExecdWorkerCompletion completion{};
    completion.reply_status = EXECD_WORKER_REPLY_SUCCESS;
    completion.plan = Plan(request, seed);
    return completion;
}

ExecdWorkerCompletion Failure(ExecdWorkerReplyStatus status = EXECD_WORKER_REPLY_INVALID_IMAGE)
{
    ExecdWorkerCompletion completion{};
    completion.reply_status = status;
    return completion;
}

ExecdWorkerPeerReceipt Open(ExecdWorker& worker, const ExecdWorkerPeerIdentity& peer,
                            std::uint64_t first_request_id = 1)
{
    ExecdWorkerPeerReceipt receipt{};
    EXPECT_EQ(ExecdWorkerOpenPeer(&worker, &peer, first_request_id, &receipt), EXECD_WORKER_OK);
    return receipt;
}

ExecdWorkerRequestReceipt Submit(ExecdWorker& worker, const ExecdWorkerPeerReceipt& peer,
                                 const ExecdWorkerParseRequest& request)
{
    ExecdWorkerRequestReceipt receipt{};
    EXPECT_EQ(ExecdWorkerSubmit(&worker, &peer, &request, &receipt), EXECD_WORKER_OK);
    return receipt;
}

ExecdWorkerWorkItem Claim(ExecdWorker& worker)
{
    ExecdWorkerWorkItem work{};
    EXPECT_EQ(ExecdWorkerClaimNext(&worker, &work), EXECD_WORKER_OK);
    return work;
}

ExecdWorkerReplyPublication NextReply(ExecdWorker& worker)
{
    ExecdWorkerReplyPublication reply{};
    EXPECT_EQ(ExecdWorkerGetNextReply(&worker, &reply), EXECD_WORKER_OK);
    return reply;
}

ExecdWorkerCleanupRecord CommitReply(ExecdWorker& worker, const ExecdWorkerReplyPublication& reply)
{
    ExecdWorkerCleanupRecord cleanup{};
    EXPECT_EQ(ExecdWorkerCommitReply(&worker, &reply.lease, &cleanup), EXECD_WORKER_OK);
    return cleanup;
}

void Initialize(ExecdWorker& worker, std::uint64_t first_generation = 1)
{
    const auto instance = Instance();
    EXPECT_EQ(ExecdWorkerInitialize(&worker, &instance, first_generation), EXECD_WORKER_OK);
}

void TestInitializationAndIdentity()
{
    const auto instance = Instance();
    ExecdWorkerSnapshot snapshot{};

    EXPECT_TRUE(ExecdWorkerInstanceIdentityIsCanonical(&instance));
    EXPECT_EQ(ExecdWorkerInitialize(&g_workers[0], &instance, 1), EXECD_WORKER_OK);
    EXPECT_EQ(ExecdWorkerDescribe(&g_workers[0], &snapshot), EXECD_WORKER_OK);
    EXPECT_EQ(snapshot.state, static_cast<std::uint32_t>(EXECD_WORKER_STATE_OPEN));
    EXPECT_EQ(snapshot.peer_count, 0U);
    EXPECT_EQ(snapshot.request_count, 0U);
    EXPECT_EQ(ExecdWorkerInitialize(&g_workers[0], &instance, 1), EXECD_WORKER_ALREADY_INITIALIZED);

    auto invalid = instance;
    invalid.process.identity = 0;
    EXPECT_FALSE(ExecdWorkerInstanceIdentityIsCanonical(&invalid));
    EXPECT_EQ(ExecdWorkerInitialize(&g_workers[1], &invalid, 1), EXECD_WORKER_INVALID_IDENTITY);
    EXPECT_EQ(ExecdWorkerInitialize(&g_workers[1], &instance, 0), EXECD_WORKER_INVALID_IDENTITY);
    EXPECT_EQ(ExecdWorkerInitialize(&g_workers[1],
                                    reinterpret_cast<const ExecdWorkerInstanceIdentity*>(g_workers[1].bytes), 1),
              EXECD_WORKER_ALIASED_STORAGE);
    g_workers[2].bytes[0] = 1;
    EXPECT_EQ(ExecdWorkerInitialize(&g_workers[2], &instance, 1), EXECD_WORKER_NONZERO_STORAGE);
    EXPECT_EQ(ExecdWorkerDescribe(&g_workers[0], reinterpret_cast<ExecdWorkerSnapshot*>(g_workers[0].bytes)),
              EXECD_WORKER_ALIASED_STORAGE);
    EXPECT_STREQ(ExecdWorkerStatusName(EXECD_WORKER_STALE_WORK), "stale-work");
    EXPECT_STREQ(ExecdWorkerStatusName(static_cast<ExecdWorkerStatus>(31)), "unknown");
}

void TestPeerAndRequestOrdering()
{
    Initialize(g_workers[3]);
    const auto peer_identity = Peer(1);
    const auto peer = Open(g_workers[3], peer_identity);
    ExecdWorkerPeerReceipt duplicate{};
    EXPECT_EQ(ExecdWorkerOpenPeer(&g_workers[3], &peer_identity, 1, &duplicate), EXECD_WORKER_PEER_EXISTS);

    auto stale_peer = peer;
    ++stale_peer.peer.channel_epoch;
    const auto first = Request(1, 1);
    ExecdWorkerRequestReceipt receipt{};
    EXPECT_EQ(ExecdWorkerSubmit(&g_workers[3], &stale_peer, &first, &receipt), EXECD_WORKER_STALE_PEER);
    auto malformed = first;
    malformed.source.sealed = 0;
    EXPECT_EQ(ExecdWorkerSubmit(&g_workers[3], &peer, &malformed, &receipt), EXECD_WORKER_INVALID_ARGUMENT);
    const auto second = Request(2, 2);
    EXPECT_EQ(ExecdWorkerSubmit(&g_workers[3], &peer, &second, &receipt), EXECD_WORKER_OUT_OF_ORDER_REQUEST);

    const auto accepted = Submit(g_workers[3], peer, first);
    ExecdWorkerRequestSnapshot request_snapshot{};
    EXPECT_EQ(ExecdWorkerInspectRequest(&g_workers[3], &accepted, &request_snapshot), EXECD_WORKER_OK);
    EXPECT_EQ(request_snapshot.phase, static_cast<std::uint32_t>(EXECD_WORKER_REQUEST_QUEUED));
    EXPECT_TRUE(request_snapshot.source_retained);
    EXPECT_EQ(ExecdWorkerSubmit(&g_workers[3], &peer, &first, &receipt), EXECD_WORKER_REPLAYED_REQUEST);

    ExecdWorkerCleanupBatch cleanup{};
    EXPECT_EQ(ExecdWorkerClosePeer(&g_workers[3], &peer, &cleanup), EXECD_WORKER_OK);
    EXPECT_EQ(cleanup.count, 1U);
    EXPECT_TRUE(cleanup.records[0].release_source_import);
    EXPECT_EQ(cleanup.records[0].source_object_identity, first.source.object_identity);
    EXPECT_EQ(ExecdWorkerSubmit(&g_workers[3], &peer, &second, &receipt), EXECD_WORKER_STALE_PEER);
    const auto reopened = Open(g_workers[3], peer_identity);
    EXPECT_NE(reopened.peer_slot, peer.peer_slot);
    EXPECT_EQ(ExecdWorkerClosePeer(&g_workers[3], &reopened, &cleanup), EXECD_WORKER_OK);
    for (std::uint64_t index = 0; index < EXECD_WORKER_MAX_PEERS - 2U; ++index)
    {
        const auto filler = Open(g_workers[3], Peer(1000 + index));
        EXPECT_EQ(ExecdWorkerClosePeer(&g_workers[3], &filler, &cleanup), EXECD_WORKER_OK);
    }
    const auto reused = Open(g_workers[3], peer_identity);
    EXPECT_EQ(reused.peer_slot, peer.peer_slot);
    EXPECT_NE(reused.peer_generation, peer.peer_generation);
    EXPECT_EQ(ExecdWorkerClosePeer(&g_workers[3], &peer, &cleanup), EXECD_WORKER_STALE_PEER);
    EXPECT_EQ(ExecdWorkerClosePeer(&g_workers[3], &reused, &cleanup), EXECD_WORKER_OK);
}

void TestSuccessReplyTransaction()
{
    Initialize(g_workers[4]);
    const auto peer = Open(g_workers[4], Peer(2));
    const auto request = Request(1, 10, EXECD_WORKER_FORMAT_PE32_PLUS);
    const auto receipt = Submit(g_workers[4], peer, request);
    const auto work = Claim(g_workers[4]);
    std::uint8_t cancelled = 1;
    EXPECT_EQ(work.lease.request.request_id, receipt.request_id);
    EXPECT_EQ(ExecdWorkerCheckCancellation(&g_workers[4], &work.lease, &cancelled), EXECD_WORKER_OK);
    EXPECT_FALSE(cancelled);

    const auto completion = Success(request, 10);
    auto completed = ExecdWorkerComplete(&g_workers[4], &work.lease, &completion);
    EXPECT_EQ(completed.status, EXECD_WORKER_OK);
    EXPECT_TRUE(completed.reply_ready);
    EXPECT_TRUE(completed.cleanup.release_source_import);
    EXPECT_EQ(completed.cleanup.plan_disposition, static_cast<std::uint8_t>(EXECD_WORKER_PLAN_NONE));

    ExecdWorkerRequestSnapshot request_snapshot{};
    EXPECT_EQ(ExecdWorkerInspectRequest(&g_workers[4], &receipt, &request_snapshot), EXECD_WORKER_OK);
    EXPECT_EQ(request_snapshot.phase, static_cast<std::uint32_t>(EXECD_WORKER_REQUEST_REPLY_READY));
    EXPECT_FALSE(request_snapshot.source_retained);
    EXPECT_TRUE(request_snapshot.plan_retained);

    auto reply = NextReply(g_workers[4]);
    EXPECT_EQ(reply.reply.request_id, request.request_id);
    EXPECT_EQ(reply.reply.status, static_cast<std::uint32_t>(EXECD_WORKER_REPLY_SUCCESS));
    EXPECT_EQ(reply.reply.load_plan_object_ref, completion.plan.transfer_reference);
    EXPECT_TRUE(std::memcmp(reply.reply.source_hash, request.source.source_hash, 32) == 0);
    ExecdWorkerReplyPublication no_reply{};
    EXPECT_EQ(ExecdWorkerGetNextReply(&g_workers[4], &no_reply), EXECD_WORKER_REPLY_IN_FLIGHT);
    EXPECT_EQ(ExecdWorkerCancel(&g_workers[4], &peer, request.request_id).status, EXECD_WORKER_CANCEL_TOO_LATE);
    EXPECT_EQ(ExecdWorkerAbortReply(&g_workers[4], &reply.lease), EXECD_WORKER_OK);
    reply = NextReply(g_workers[4]);
    const auto cleanup = CommitReply(g_workers[4], reply);
    EXPECT_FALSE(cleanup.release_source_import);
    EXPECT_EQ(cleanup.plan_disposition, static_cast<std::uint8_t>(EXECD_WORKER_PLAN_PUBLISHED));
    EXPECT_EQ(cleanup.plan_object_identity, completion.plan.object_identity);
    ExecdWorkerCleanupRecord replay_cleanup{};
    EXPECT_EQ(ExecdWorkerCommitReply(&g_workers[4], &reply.lease, &replay_cleanup), EXECD_WORKER_STALE_REPLY);
    EXPECT_EQ(ExecdWorkerInspectRequest(&g_workers[4], &receipt, &request_snapshot), EXECD_WORKER_STALE_WORK);

    const auto invalid_request = Request(2, 11);
    Submit(g_workers[4], peer, invalid_request);
    const auto invalid_work = Claim(g_workers[4]);
    auto invalid_completion = Success(invalid_request, 11);
    invalid_completion.plan.source_hash[0] ^= 0x55U;
    auto invalid_result = ExecdWorkerComplete(&g_workers[4], &invalid_work.lease, &invalid_completion);
    EXPECT_EQ(invalid_result.status, EXECD_WORKER_INVALID_COMPLETION);
    EXPECT_EQ(ExecdWorkerInspectRequest(&g_workers[4], &invalid_work.lease.request, &request_snapshot),
              EXECD_WORKER_OK);
    EXPECT_EQ(request_snapshot.phase, static_cast<std::uint32_t>(EXECD_WORKER_REQUEST_RUNNING));
    const auto failure = Failure();
    auto failure_result = ExecdWorkerComplete(&g_workers[4], &invalid_work.lease, &failure);
    EXPECT_EQ(failure_result.status, EXECD_WORKER_OK);
    EXPECT_TRUE(failure_result.cleanup.release_source_import);
    const auto second_failure_request = Request(3, 12);
    Submit(g_workers[4], peer, second_failure_request);
    const auto second_failure_work = Claim(g_workers[4]);
    EXPECT_EQ(ExecdWorkerComplete(&g_workers[4], &second_failure_work.lease, &failure).status, EXECD_WORKER_OK);
    auto failure_reply = NextReply(g_workers[4]);
    EXPECT_EQ(failure_reply.reply.status, static_cast<std::uint32_t>(EXECD_WORKER_REPLY_INVALID_IMAGE));
    EXPECT_EQ(ExecdWorkerGetNextReply(&g_workers[4], &no_reply), EXECD_WORKER_REPLY_IN_FLIGHT);
    const auto failure_cleanup = CommitReply(g_workers[4], failure_reply);
    EXPECT_EQ(failure_cleanup.plan_disposition, static_cast<std::uint8_t>(EXECD_WORKER_PLAN_NONE));
    failure_reply = NextReply(g_workers[4]);
    EXPECT_EQ(failure_reply.reply.request_id, second_failure_request.request_id);
    CommitReply(g_workers[4], failure_reply);

    ExecdWorkerSnapshot snapshot{};
    EXPECT_EQ(ExecdWorkerDescribe(&g_workers[4], &snapshot), EXECD_WORKER_OK);
    EXPECT_EQ(snapshot.request_count, 0U);
    ExecdWorkerCleanupBatch peer_cleanup{};
    EXPECT_EQ(ExecdWorkerClosePeer(&g_workers[4], &peer, &peer_cleanup), EXECD_WORKER_OK);
    EXPECT_EQ(peer_cleanup.count, 0U);
}

void TestCancellationLinearization()
{
    Initialize(g_workers[5]);
    const auto peer = Open(g_workers[5], Peer(3));

    const auto queued_request = Request(1, 20);
    Submit(g_workers[5], peer, queued_request);
    auto queued_cancel = ExecdWorkerCancel(&g_workers[5], &peer, 1);
    EXPECT_EQ(queued_cancel.status, EXECD_WORKER_OK);
    EXPECT_TRUE(queued_cancel.cancellation_requested);
    EXPECT_TRUE(queued_cancel.reply_ready);
    EXPECT_TRUE(queued_cancel.cleanup.release_source_import);
    EXPECT_EQ(ExecdWorkerCancel(&g_workers[5], &peer, 1).status, EXECD_WORKER_REPLAYED_REQUEST);
    auto queued_reply = NextReply(g_workers[5]);
    EXPECT_EQ(queued_reply.reply.status, static_cast<std::uint32_t>(EXECD_WORKER_REPLY_CANCELLED));
    CommitReply(g_workers[5], queued_reply);

    const auto running_request = Request(2, 21);
    Submit(g_workers[5], peer, running_request);
    const auto running_work = Claim(g_workers[5]);
    auto running_cancel = ExecdWorkerCancel(&g_workers[5], &peer, 2);
    EXPECT_EQ(running_cancel.status, EXECD_WORKER_OK);
    EXPECT_TRUE(running_cancel.cancellation_requested);
    std::uint8_t cancelled = 0;
    EXPECT_EQ(ExecdWorkerCheckCancellation(&g_workers[5], &running_work.lease, &cancelled), EXECD_WORKER_OK);
    EXPECT_TRUE(cancelled);
    const auto cancelled_success = Success(running_request, 21);
    auto cancelled_completion = ExecdWorkerComplete(&g_workers[5], &running_work.lease, &cancelled_success);
    EXPECT_EQ(cancelled_completion.status, EXECD_WORKER_OK);
    EXPECT_TRUE(cancelled_completion.cleanup.release_source_import);
    EXPECT_EQ(cancelled_completion.cleanup.plan_disposition, static_cast<std::uint8_t>(EXECD_WORKER_PLAN_DISCARD));
    auto running_reply = NextReply(g_workers[5]);
    EXPECT_EQ(running_reply.reply.status, static_cast<std::uint32_t>(EXECD_WORKER_REPLY_CANCELLED));
    CommitReply(g_workers[5], running_reply);

    const auto ready_request = Request(3, 22);
    Submit(g_workers[5], peer, ready_request);
    const auto ready_work = Claim(g_workers[5]);
    const auto ready_success = Success(ready_request, 22);
    EXPECT_EQ(ExecdWorkerComplete(&g_workers[5], &ready_work.lease, &ready_success).status, EXECD_WORKER_OK);
    auto ready_cancel = ExecdWorkerCancel(&g_workers[5], &peer, 3);
    EXPECT_EQ(ready_cancel.status, EXECD_WORKER_OK);
    EXPECT_EQ(ready_cancel.cleanup.plan_disposition, static_cast<std::uint8_t>(EXECD_WORKER_PLAN_DISCARD));
    auto ready_reply = NextReply(g_workers[5]);
    EXPECT_EQ(ready_reply.reply.status, static_cast<std::uint32_t>(EXECD_WORKER_REPLY_CANCELLED));
    CommitReply(g_workers[5], ready_reply);

    const auto publishing_request = Request(4, 23);
    Submit(g_workers[5], peer, publishing_request);
    const auto publishing_work = Claim(g_workers[5]);
    const auto service_failure = Failure(EXECD_WORKER_REPLY_SERVICE_FAILURE);
    EXPECT_EQ(ExecdWorkerComplete(&g_workers[5], &publishing_work.lease, &service_failure).status, EXECD_WORKER_OK);
    auto publishing_reply = NextReply(g_workers[5]);
    EXPECT_EQ(ExecdWorkerCancel(&g_workers[5], &peer, 4).status, EXECD_WORKER_CANCEL_TOO_LATE);
    CommitReply(g_workers[5], publishing_reply);

    ExecdWorkerCleanupBatch cleanup{};
    EXPECT_EQ(ExecdWorkerClosePeer(&g_workers[5], &peer, &cleanup), EXECD_WORKER_OK);
}

void TestPeerCloseAndDrain()
{
    Initialize(g_workers[6]);
    const auto peer_a = Open(g_workers[6], Peer(30));
    const auto peer_b = Open(g_workers[6], Peer(31));
    const auto running_request = Request(1, 30);
    Submit(g_workers[6], peer_a, running_request);
    const auto running_work = Claim(g_workers[6]);
    const auto ready_request = Request(1, 31);
    Submit(g_workers[6], peer_b, ready_request);
    const auto ready_work = Claim(g_workers[6]);
    const auto ready_completion = Success(ready_request, 31);
    EXPECT_EQ(ExecdWorkerComplete(&g_workers[6], &ready_work.lease, &ready_completion).status, EXECD_WORKER_OK);
    const auto queued_request = Request(2, 32);
    Submit(g_workers[6], peer_a, queued_request);

    ExecdWorkerCleanupBatch peer_cleanup{};
    EXPECT_EQ(ExecdWorkerClosePeer(&g_workers[6], &peer_a, &peer_cleanup), EXECD_WORKER_OK);
    EXPECT_EQ(peer_cleanup.count, 1U);
    EXPECT_TRUE(peer_cleanup.records[0].release_source_import);
    EXPECT_EQ(peer_cleanup.records[0].source_object_identity, queued_request.source.object_identity);
    std::uint8_t cancelled = 0;
    EXPECT_EQ(ExecdWorkerCheckCancellation(&g_workers[6], &running_work.lease, &cancelled), EXECD_WORKER_OK);
    EXPECT_TRUE(cancelled);
    const auto running_completion = Success(running_request, 30);
    const auto discarded = ExecdWorkerComplete(&g_workers[6], &running_work.lease, &running_completion);
    EXPECT_EQ(discarded.status, EXECD_WORKER_OK);
    EXPECT_TRUE(discarded.request_discarded);
    EXPECT_FALSE(discarded.reply_ready);
    EXPECT_TRUE(discarded.cleanup.release_source_import);
    EXPECT_EQ(discarded.cleanup.plan_disposition, static_cast<std::uint8_t>(EXECD_WORKER_PLAN_DISCARD));
    EXPECT_EQ(ExecdWorkerClosePeer(&g_workers[6], &peer_a, &peer_cleanup), EXECD_WORKER_STALE_PEER);

    EXPECT_EQ(ExecdWorkerClosePeer(&g_workers[6], &peer_b, &peer_cleanup), EXECD_WORKER_OK);
    EXPECT_EQ(peer_cleanup.count, 1U);
    EXPECT_FALSE(peer_cleanup.records[0].release_source_import);
    EXPECT_EQ(peer_cleanup.records[0].plan_disposition, static_cast<std::uint8_t>(EXECD_WORKER_PLAN_DISCARD));

    Initialize(g_workers[7]);
    const auto drain_peer_a = Open(g_workers[7], Peer(40));
    const auto drain_peer_b = Open(g_workers[7], Peer(41));
    const auto drain_running_request = Request(1, 40);
    Submit(g_workers[7], drain_peer_a, drain_running_request);
    const auto drain_running_work = Claim(g_workers[7]);
    const auto drain_ready_request = Request(1, 41);
    Submit(g_workers[7], drain_peer_b, drain_ready_request);
    const auto drain_ready_work = Claim(g_workers[7]);
    const auto drain_ready_completion = Success(drain_ready_request, 41);
    EXPECT_EQ(ExecdWorkerComplete(&g_workers[7], &drain_ready_work.lease, &drain_ready_completion).status,
              EXECD_WORKER_OK);
    const auto drain_queued_request = Request(2, 42);
    Submit(g_workers[7], drain_peer_a, drain_queued_request);

    ExecdWorkerCleanupBatch drain_cleanup{};
    EXPECT_EQ(ExecdWorkerBeginDrain(&g_workers[7], &drain_cleanup), EXECD_WORKER_OK);
    EXPECT_EQ(drain_cleanup.count, 2U);
    EXPECT_EQ(ExecdWorkerFinishDrain(&g_workers[7]), EXECD_WORKER_BUSY);
    cancelled = 0;
    EXPECT_EQ(ExecdWorkerCheckCancellation(&g_workers[7], &drain_running_work.lease, &cancelled), EXECD_WORKER_OK);
    EXPECT_TRUE(cancelled);
    const auto drain_success = Success(drain_running_request, 40);
    const auto drain_completion = ExecdWorkerComplete(&g_workers[7], &drain_running_work.lease, &drain_success);
    EXPECT_EQ(drain_completion.status, EXECD_WORKER_OK);
    EXPECT_TRUE(drain_completion.request_discarded);
    EXPECT_TRUE(drain_completion.cleanup.release_source_import);
    EXPECT_EQ(drain_completion.cleanup.plan_disposition, static_cast<std::uint8_t>(EXECD_WORKER_PLAN_DISCARD));
    EXPECT_EQ(ExecdWorkerFinishDrain(&g_workers[7]), EXECD_WORKER_OK);
    ExecdWorkerSnapshot snapshot{};
    EXPECT_EQ(ExecdWorkerDescribe(&g_workers[7], &snapshot), EXECD_WORKER_OK);
    EXPECT_EQ(snapshot.state, static_cast<std::uint32_t>(EXECD_WORKER_STATE_CLOSED));
    EXPECT_EQ(snapshot.peer_count, 0U);
    EXPECT_EQ(snapshot.request_count, 0U);
    EXPECT_EQ(ExecdWorkerBeginDrain(&g_workers[7], &drain_cleanup), EXECD_WORKER_CLOSED);
}

void TestGenerationAndSequenceExhaustion()
{
    Initialize(g_workers[8], UINT64_MAX);
    ExecdWorkerCleanupBatch cleanup{};
    for (std::uint64_t index = 0; index < EXECD_WORKER_MAX_PEERS; ++index)
    {
        const auto peer = Open(g_workers[8], Peer(100 + index));
        EXPECT_EQ(ExecdWorkerClosePeer(&g_workers[8], &peer, &cleanup), EXECD_WORKER_OK);
        EXPECT_EQ(cleanup.count, 0U);
    }
    ExecdWorkerPeerReceipt peer_receipt{};
    const auto overflow_peer = Peer(200);
    EXPECT_EQ(ExecdWorkerOpenPeer(&g_workers[8], &overflow_peer, 1, &peer_receipt), EXECD_WORKER_GENERATION_EXHAUSTED);
    ExecdWorkerSnapshot snapshot{};
    EXPECT_EQ(ExecdWorkerDescribe(&g_workers[8], &snapshot), EXECD_WORKER_OK);
    EXPECT_EQ(snapshot.retired_peer_slots, EXECD_WORKER_MAX_PEERS);

    Initialize(g_workers[9], UINT64_MAX);
    const auto request_peer = Open(g_workers[9], Peer(201));
    for (std::uint64_t request_id = 1; request_id <= EXECD_WORKER_MAX_REQUESTS; ++request_id)
    {
        const auto request = Request(request_id, 300 + request_id);
        Submit(g_workers[9], request_peer, request);
        const auto work = Claim(g_workers[9]);
        const auto failure = Failure();
        EXPECT_EQ(ExecdWorkerComplete(&g_workers[9], &work.lease, &failure).status, EXECD_WORKER_OK);
        CommitReply(g_workers[9], NextReply(g_workers[9]));
    }
    const auto exhausted_request = Request(EXECD_WORKER_MAX_REQUESTS + 1U, 400);
    ExecdWorkerRequestReceipt request_receipt{};
    EXPECT_EQ(ExecdWorkerSubmit(&g_workers[9], &request_peer, &exhausted_request, &request_receipt),
              EXECD_WORKER_GENERATION_EXHAUSTED);
    EXPECT_EQ(ExecdWorkerDescribe(&g_workers[9], &snapshot), EXECD_WORKER_OK);
    EXPECT_EQ(snapshot.retired_request_slots, EXECD_WORKER_MAX_REQUESTS);
    EXPECT_EQ(ExecdWorkerClosePeer(&g_workers[9], &request_peer, &cleanup), EXECD_WORKER_OK);

    Initialize(g_workers[10]);
    const auto sequence_peer = Open(g_workers[10], Peer(202), UINT64_MAX);
    const auto final_request = Request(UINT64_MAX, 500);
    Submit(g_workers[10], sequence_peer, final_request);
    const auto final_work = Claim(g_workers[10]);
    const auto final_failure = Failure();
    EXPECT_EQ(ExecdWorkerComplete(&g_workers[10], &final_work.lease, &final_failure).status, EXECD_WORKER_OK);
    CommitReply(g_workers[10], NextReply(g_workers[10]));
    const auto wrapped_request = Request(1, 501);
    EXPECT_EQ(ExecdWorkerSubmit(&g_workers[10], &sequence_peer, &wrapped_request, &request_receipt),
              EXECD_WORKER_SEQUENCE_EXHAUSTED);
    EXPECT_EQ(ExecdWorkerClosePeer(&g_workers[10], &sequence_peer, &cleanup), EXECD_WORKER_OK);
}

void TestCapacityDoesNotAdvanceSequence()
{
    Initialize(g_workers[11]);
    const auto peer = Open(g_workers[11], Peer(250));
    for (std::uint64_t request_id = 1; request_id <= EXECD_WORKER_MAX_REQUESTS; ++request_id)
        Submit(g_workers[11], peer, Request(request_id, 600 + request_id));

    const auto over_capacity = Request(EXECD_WORKER_MAX_REQUESTS + 1U, 700);
    ExecdWorkerRequestReceipt receipt{};
    EXPECT_EQ(ExecdWorkerSubmit(&g_workers[11], &peer, &over_capacity, &receipt), EXECD_WORKER_REQUEST_CAPACITY);
    const auto work = Claim(g_workers[11]);
    const auto failure = Failure();
    EXPECT_EQ(ExecdWorkerComplete(&g_workers[11], &work.lease, &failure).status, EXECD_WORKER_OK);
    CommitReply(g_workers[11], NextReply(g_workers[11]));
    EXPECT_EQ(ExecdWorkerSubmit(&g_workers[11], &peer, &over_capacity, &receipt), EXECD_WORKER_OK);
    EXPECT_EQ(receipt.request_slot, work.lease.request.request_slot);
    EXPECT_NE(receipt.request_generation, work.lease.request.request_generation);
    std::uint8_t cancelled = 0;
    EXPECT_EQ(ExecdWorkerCheckCancellation(&g_workers[11], &work.lease, &cancelled), EXECD_WORKER_STALE_WORK);

    ExecdWorkerCleanupBatch cleanup{};
    EXPECT_EQ(ExecdWorkerBeginDrain(&g_workers[11], &cleanup), EXECD_WORKER_OK);
    EXPECT_EQ(cleanup.count, EXECD_WORKER_MAX_REQUESTS);
    EXPECT_EQ(ExecdWorkerFinishDrain(&g_workers[11]), EXECD_WORKER_OK);
}

} // namespace

int main()
{
    TestInitializationAndIdentity();
    TestPeerAndRequestOrdering();
    TestSuccessReplyTransaction();
    TestCancellationLinearization();
    TestPeerCloseAndDrain();
    TestGenerationAndSequenceExhaustion();
    TestCapacityDoesNotAdvanceSequence();
    return duetos_host_test::finish_main("execd worker hostile-state tests");
}
