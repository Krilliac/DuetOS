// Hosted hostile-state coverage for the allocation-free displayd engine.

#include "display_engine_internal.h"
#include "host_test_helper.h"

#include <cstdint>
#include <cstring>
#include <limits>

namespace
{

DisplaydEngine g_engines[10]{};

DisplaydEngineInstanceIdentity Instance(std::uint64_t generation = 7)
{
    return DisplaydEngineInstanceIdentity{
        DISPLAYD_ENGINE_SERVICE_IDENTITY,   generation, {0x4453504c50000000ULL | generation, 300},
        0x45504f4348000000ULL | generation, 2,          0};
}

DisplaydPeerIdentity Peer(std::uint64_t seed)
{
    DisplaydPeerIdentity peer{};
    peer.process = {0x5000000000000000ULL | seed, 1000 + seed};
    peer.credential = {static_cast<std::uint32_t>(seed % 64U), 0, 0x6000000000000ULL | seed};
    peer.channel.slot = static_cast<std::uint32_t>(seed % DISPLAYD_ENGINE_CHANNEL_SLOT_CAPACITY);
    peer.channel.role = DISPLAYD_CHANNEL_ROLE_INITIATOR;
    peer.channel.generation = 0x7000000000000ULL | seed;
    peer.channel.epoch = 0x8000000000000000ULL | seed;
    peer.integrity = 3;
    return peer;
}

DisplaydRect Rect(std::int32_t x, std::int32_t y, std::uint32_t width = 120, std::uint32_t height = 80)
{
    return DisplaydRect{x, y, width, height};
}

DisplaydRequest Create(std::uint64_t request_id, DisplaydRect bounds, bool visible)
{
    DisplaydRequest request{};
    request.request_id = request_id;
    request.bounds = bounds;
    request.command = DISPLAYD_COMMAND_CREATE_SURFACE;
    request.visible = visible ? 1 : 0;
    return request;
}

DisplaydRequest SurfaceRequest(std::uint64_t request_id, DisplaydCommandType command,
                               const DisplaydSurfaceIdentity& surface)
{
    DisplaydRequest request{};
    request.request_id = request_id;
    request.surface = surface;
    request.command = static_cast<std::uint8_t>(command);
    return request;
}

bool SameSurface(const DisplaydSurfaceIdentity& left, const DisplaydSurfaceIdentity& right)
{
    return left.instance.service_identity == right.instance.service_identity &&
           left.instance.instance_generation == right.instance.instance_generation &&
           left.instance.process.identity == right.instance.process.identity &&
           left.instance.process.pid == right.instance.process.pid &&
           left.instance.published_endpoint_epoch == right.instance.published_endpoint_epoch &&
           left.instance.service_slot == right.instance.service_slot && left.generation == right.generation &&
           left.slot == right.slot;
}

void Initialize(DisplaydEngine& engine, std::uint64_t first_generation = 1)
{
    const auto instance = Instance(first_generation == UINT64_MAX ? 99 : first_generation + 10);
    EXPECT_EQ(DisplaydEngineInitialize(&engine, &instance, first_generation, 1024, 768), DISPLAYD_ENGINE_OK);
}

DisplaydPeerReceipt Open(DisplaydEngine& engine, const DisplaydPeerIdentity& peer, std::uint64_t first_request_id = 1)
{
    DisplaydPeerReceipt receipt{};
    EXPECT_EQ(DisplaydEngineOpenPeer(&engine, &peer, first_request_id, &receipt), DISPLAYD_ENGINE_OK);
    EXPECT_TRUE(DisplaydPeerReceiptIsCanonical(&receipt));
    return receipt;
}

DisplaydRequestReceipt Submit(DisplaydEngine& engine, const DisplaydPeerReceipt& peer, const DisplaydRequest& request)
{
    DisplaydRequestReceipt receipt{};
    EXPECT_EQ(DisplaydEngineSubmit(&engine, &peer, &request, &receipt), DISPLAYD_ENGINE_OK);
    return receipt;
}

DisplaydApplyResult Apply(DisplaydEngine& engine)
{
    DisplaydApplyResult result{};
    EXPECT_EQ(DisplaydEngineApplyNext(&engine, &result), DISPLAYD_ENGINE_OK);
    return result;
}

DisplaydReply CommitNextReply(DisplaydEngine& engine, const DisplaydPeerReceipt& peer)
{
    DisplaydReplyPublication publication{};
    EXPECT_EQ(DisplaydEngineGetNextReply(&engine, &peer, &publication), DISPLAYD_ENGINE_OK);
    const DisplaydReply reply = publication.reply;
    EXPECT_EQ(DisplaydEngineCommitReply(&engine, &publication.lease), DISPLAYD_ENGINE_OK);
    return reply;
}

std::uint32_t DrainEvents(DisplaydEngine& engine, const DisplaydPeerReceipt& peer, DisplaydEvent* captured = nullptr,
                          std::uint32_t capture_capacity = 0)
{
    std::uint32_t count = 0;
    for (;;)
    {
        DisplaydEventPublication publication{};
        const auto status = DisplaydEngineGetNextEvent(&engine, &peer, &publication);
        if (status == DISPLAYD_ENGINE_NO_EVENT)
            break;
        EXPECT_EQ(status, DISPLAYD_ENGINE_OK);
        if (status != DISPLAYD_ENGINE_OK)
            break;
        if (captured != nullptr && count < capture_capacity)
            captured[count] = publication.event;
        ++count;
        EXPECT_EQ(DisplaydEngineCommitEvent(&engine, &publication.lease), DISPLAYD_ENGINE_OK);
    }
    return count;
}

DisplaydSurfaceIdentity CreateSurface(DisplaydEngine& engine, const DisplaydPeerReceipt& peer, std::uint64_t request_id,
                                      DisplaydRect bounds, bool visible)
{
    Submit(engine, peer, Create(request_id, bounds, visible));
    const auto applied = Apply(engine);
    EXPECT_EQ(applied.reply.code, static_cast<std::uint32_t>(DISPLAYD_REPLY_SUCCESS));
    EXPECT_TRUE(DisplaydSurfaceIdentityIsCanonical(&applied.reply.surface));
    const auto reply = CommitNextReply(engine, peer);
    EXPECT_TRUE(SameSurface(reply.surface, applied.reply.surface));
    return applied.reply.surface;
}

DisplaydReply ApplySurfaceRequest(DisplaydEngine& engine, const DisplaydPeerReceipt& peer,
                                  const DisplaydRequest& request)
{
    Submit(engine, peer, request);
    const auto applied = Apply(engine);
    const auto published = CommitNextReply(engine, peer);
    EXPECT_EQ(published.code, applied.reply.code);
    return applied.reply;
}

void TestInitializationAndIdentity()
{
    DisplaydEngineInstanceIdentity bad = Instance();
    bad.service_identity = 0x301;
    EXPECT_EQ(DisplaydEngineInitialize(&g_engines[0], &bad, 1, 1024, 768), DISPLAYD_ENGINE_INVALID_INSTANCE);
    EXPECT_EQ(DisplaydEngineInitialize(&g_engines[0], reinterpret_cast<DisplaydEngineInstanceIdentity*>(&g_engines[0]),
                                       1, 1024, 768),
              DISPLAYD_ENGINE_ALIASED_STORAGE);
    bad = Instance();
    bad.service_slot = DISPLAYD_ENGINE_SERVICE_CAPACITY;
    EXPECT_EQ(DisplaydEngineInitialize(&g_engines[0], &bad, 1, 1024, 768), DISPLAYD_ENGINE_INVALID_INSTANCE);
    const auto instance = Instance();
    EXPECT_EQ(DisplaydEngineInitialize(&g_engines[0], &instance, 1, 1024, 768), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(DisplaydEngineInitialize(&g_engines[0], &instance, 1, 1024, 768), DISPLAYD_ENGINE_ALREADY_INITIALIZED);

    auto invalid_peer = Peer(1);
    invalid_peer.credential.generation = 0;
    DisplaydPeerReceipt receipt{};
    EXPECT_EQ(DisplaydEngineOpenPeer(&g_engines[0], &invalid_peer, 1, &receipt), DISPLAYD_ENGINE_INVALID_IDENTITY);
    invalid_peer = Peer(1);
    invalid_peer.credential.generation = DISPLAYD_ENGINE_CREDENTIAL_GENERATION_MAX + 1U;
    EXPECT_EQ(DisplaydEngineOpenPeer(&g_engines[0], &invalid_peer, 1, &receipt), DISPLAYD_ENGINE_INVALID_IDENTITY);
    invalid_peer = Peer(1);
    invalid_peer.channel.role = DISPLAYD_CHANNEL_ROLE_INVALID;
    EXPECT_EQ(DisplaydEngineOpenPeer(&g_engines[0], &invalid_peer, 1, &receipt), DISPLAYD_ENGINE_INVALID_IDENTITY);

    const auto peer_identity = Peer(2);
    alignas(DisplaydPeerReceipt) std::uint8_t peer_alias[sizeof(DisplaydPeerReceipt)]{};
    std::memcpy(peer_alias, &peer_identity, sizeof(peer_identity));
    EXPECT_EQ(DisplaydEngineOpenPeer(&g_engines[0], reinterpret_cast<const DisplaydPeerIdentity*>(peer_alias), 10,
                                     reinterpret_cast<DisplaydPeerReceipt*>(peer_alias)),
              DISPLAYD_ENGINE_ALIASED_STORAGE);
    const auto peer = Open(g_engines[0], peer_identity, 10);
    EXPECT_EQ(DisplaydEngineOpenPeer(&g_engines[0], &peer_identity, 10, &receipt), DISPLAYD_ENGINE_PEER_EXISTS);
    DisplaydPeerSnapshot snapshot{};
    EXPECT_EQ(DisplaydEngineInspectPeer(&g_engines[0], &peer, &snapshot), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(snapshot.next_request_id, 10ULL);

    auto stale = peer;
    ++stale.peer.credential.generation;
    EXPECT_EQ(DisplaydEngineInspectPeer(&g_engines[0], &stale, &snapshot), DISPLAYD_ENGINE_STALE_PEER);

    auto second_identity = peer_identity;
    ++second_identity.channel.generation;
    ++second_identity.credential.generation;
    const auto second = Open(g_engines[0], second_identity, 1);
    DisplaydPeerDrainSummary summary{};
    EXPECT_EQ(DisplaydEngineClosePeer(&g_engines[0], &peer, &summary), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(DisplaydEngineInspectPeer(&g_engines[0], &peer, &snapshot), DISPLAYD_ENGINE_STALE_PEER);
    EXPECT_EQ(DisplaydEngineClosePeer(&g_engines[0], &second, &summary), DISPLAYD_ENGINE_OK);
}

void TestRequestOrderingCancellationAndPublication()
{
    Initialize(g_engines[1]);
    const auto peer = Open(g_engines[1], Peer(10), 10);

    DisplaydRequestReceipt rejected{};
    const auto replayed = Create(9, Rect(1, 1), false);
    const auto out_of_order = Create(11, Rect(1, 1), false);
    EXPECT_EQ(DisplaydEngineSubmit(&g_engines[1], &peer, &replayed, &rejected), DISPLAYD_ENGINE_REPLAYED_REQUEST);
    EXPECT_EQ(DisplaydEngineSubmit(&g_engines[1], &peer, &out_of_order, &rejected),
              DISPLAYD_ENGINE_OUT_OF_ORDER_REQUEST);

    auto malformed = Create(10, Rect(1, 1), false);
    malformed.reserved8[2] = 1;
    EXPECT_EQ(DisplaydEngineSubmit(&g_engines[1], &peer, &malformed, &rejected), DISPLAYD_ENGINE_INVALID_COMMAND);

    const auto request = Submit(g_engines[1], peer, Create(10, Rect(1, 1), false));
    DisplaydRequestSnapshot request_snapshot{};
    EXPECT_EQ(DisplaydEngineInspectRequest(&g_engines[1], &request, &request_snapshot), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(request_snapshot.phase, static_cast<std::uint8_t>(DISPLAYD_REQUEST_QUEUED));

    DisplaydRequestReceipt cancelled{};
    EXPECT_EQ(DisplaydEngineCancel(&g_engines[1], &peer, 10, &cancelled), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(cancelled.request_generation, request.request_generation);
    EXPECT_EQ(DisplaydEngineCancel(&g_engines[1], &peer, 10, &cancelled), DISPLAYD_ENGINE_CANCEL_TOO_LATE);
    DisplaydApplyResult empty_apply{};
    EXPECT_EQ(DisplaydEngineApplyNext(&g_engines[1], &empty_apply), DISPLAYD_ENGINE_NO_REQUEST);

    DisplaydReplyPublication first{};
    DisplaydReplyPublication blocked{};
    EXPECT_EQ(DisplaydEngineGetNextReply(&g_engines[1], &peer, &first), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(first.reply.code, static_cast<std::uint32_t>(DISPLAYD_REPLY_CANCELLED));
    EXPECT_EQ(DisplaydEngineGetNextReply(&g_engines[1], &peer, &blocked), DISPLAYD_ENGINE_REPLY_IN_FLIGHT);
    EXPECT_EQ(DisplaydEngineAbortReply(&g_engines[1], &first.lease), DISPLAYD_ENGINE_OK);

    DisplaydReplyPublication retried{};
    EXPECT_EQ(DisplaydEngineGetNextReply(&g_engines[1], &peer, &retried), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(retried.reply.request_id, 10ULL);
    EXPECT_EQ(DisplaydEngineCommitReply(&g_engines[1], &retried.lease), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(DisplaydEngineCommitReply(&g_engines[1], &retried.lease), DISPLAYD_ENGINE_STALE_REPLY);
    EXPECT_EQ(DisplaydEngineInspectRequest(&g_engines[1], &request, &request_snapshot), DISPLAYD_ENGINE_STALE_REPLY);

    const auto second_peer = Open(g_engines[1], Peer(11), 100);
    const auto first_receipt = Submit(g_engines[1], peer, Create(11, Rect(2, 2), false));
    const auto second_receipt = Submit(g_engines[1], second_peer, Create(100, Rect(3, 3), false));
    const auto first_applied = Apply(g_engines[1]);
    const auto second_applied = Apply(g_engines[1]);
    EXPECT_EQ(first_applied.receipt.request_generation, first_receipt.request_generation);
    EXPECT_EQ(first_applied.receipt.peer_slot, peer.slot);
    EXPECT_EQ(second_applied.receipt.request_generation, second_receipt.request_generation);
    EXPECT_EQ(second_applied.receipt.peer_slot, second_peer.slot);
    EXPECT_EQ(CommitNextReply(g_engines[1], peer).request_id, 11ULL);
    EXPECT_EQ(CommitNextReply(g_engines[1], second_peer).request_id, 100ULL);

    DisplaydEventPublication event{};
    DisplaydEventPublication event_blocked{};
    EXPECT_EQ(DisplaydEngineGetNextEvent(&g_engines[1], &peer, &event), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(DisplaydEngineGetNextEvent(&g_engines[1], &peer, &event_blocked), DISPLAYD_ENGINE_EVENT_IN_FLIGHT);
    EXPECT_EQ(DisplaydEngineAbortEvent(&g_engines[1], &event.lease), DISPLAYD_ENGINE_OK);
    DisplaydEventPublication event_retried{};
    EXPECT_EQ(DisplaydEngineGetNextEvent(&g_engines[1], &peer, &event_retried), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(event_retried.event.sequence, event.event.sequence);
    EXPECT_EQ(DisplaydEngineCommitEvent(&g_engines[1], &event_retried.lease), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(DisplaydEngineCommitEvent(&g_engines[1], &event_retried.lease), DISPLAYD_ENGINE_STALE_EVENT);
    EXPECT_EQ(DrainEvents(g_engines[1], second_peer), 1U);
}

void TestSurfaceFocusAndZOrder()
{
    Initialize(g_engines[2]);
    const auto peer_a = Open(g_engines[2], Peer(20), 1);
    const auto peer_b = Open(g_engines[2], Peer(21), 100);

    const auto surface_a = CreateSurface(g_engines[2], peer_a, 1, Rect(10, 20), true);
    DisplaydEvent events[4]{};
    EXPECT_EQ(DrainEvents(g_engines[2], peer_a, events, 4), 2U);
    EXPECT_EQ(events[0].type, static_cast<std::uint8_t>(DISPLAYD_EVENT_SURFACE_CREATED));
    EXPECT_EQ(events[1].type, static_cast<std::uint8_t>(DISPLAYD_EVENT_FOCUS_GAINED));
    EXPECT_TRUE(events[0].sequence < events[1].sequence);

    const auto surface_b = CreateSurface(g_engines[2], peer_b, 100, Rect(30, 40), true);
    EXPECT_EQ(DrainEvents(g_engines[2], peer_b, events, 4), 1U);
    EXPECT_EQ(events[0].type, static_cast<std::uint8_t>(DISPLAYD_EVENT_SURFACE_CREATED));

    DisplaydSurfaceSnapshot a_snapshot{};
    DisplaydSurfaceSnapshot b_snapshot{};
    EXPECT_EQ(DisplaydEngineInspectSurface(&g_engines[2], &surface_a, &a_snapshot), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(DisplaydEngineInspectSurface(&g_engines[2], &surface_b, &b_snapshot), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(a_snapshot.z_rank, 0U);
    EXPECT_EQ(b_snapshot.z_rank, 1U);
    EXPECT_EQ(a_snapshot.focused, 1U);
    EXPECT_EQ(b_snapshot.focused, 0U);

    auto wrong_owner = SurfaceRequest(101, DISPLAYD_COMMAND_DESTROY_SURFACE, surface_a);
    EXPECT_EQ(ApplySurfaceRequest(g_engines[2], peer_b, wrong_owner).code,
              static_cast<std::uint32_t>(DISPLAYD_REPLY_WRONG_OWNER));

    auto focus_b = SurfaceRequest(102, DISPLAYD_COMMAND_FOCUS, surface_b);
    EXPECT_EQ(ApplySurfaceRequest(g_engines[2], peer_b, focus_b).code,
              static_cast<std::uint32_t>(DISPLAYD_REPLY_SUCCESS));
    EXPECT_EQ(DrainEvents(g_engines[2], peer_a, events, 4), 1U);
    EXPECT_EQ(events[0].type, static_cast<std::uint8_t>(DISPLAYD_EVENT_FOCUS_LOST));
    EXPECT_EQ(DrainEvents(g_engines[2], peer_b, events, 4), 1U);
    EXPECT_EQ(events[0].type, static_cast<std::uint8_t>(DISPLAYD_EVENT_FOCUS_GAINED));

    auto raise_a = SurfaceRequest(2, DISPLAYD_COMMAND_RAISE, surface_a);
    EXPECT_EQ(ApplySurfaceRequest(g_engines[2], peer_a, raise_a).code,
              static_cast<std::uint32_t>(DISPLAYD_REPLY_SUCCESS));
    EXPECT_EQ(DrainEvents(g_engines[2], peer_a, events, 4), 1U);
    EXPECT_EQ(events[0].type, static_cast<std::uint8_t>(DISPLAYD_EVENT_Z_ORDER_CHANGED));
    EXPECT_EQ(DisplaydEngineInspectSurface(&g_engines[2], &surface_a, &a_snapshot), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(DisplaydEngineInspectSurface(&g_engines[2], &surface_b, &b_snapshot), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(a_snapshot.z_rank, 1U);
    EXPECT_EQ(b_snapshot.z_rank, 0U);
    EXPECT_EQ(b_snapshot.focused, 1U);

    auto bounds_b = SurfaceRequest(103, DISPLAYD_COMMAND_SET_BOUNDS, surface_b);
    bounds_b.bounds = Rect(70, 80, 200, 150);
    EXPECT_EQ(ApplySurfaceRequest(g_engines[2], peer_b, bounds_b).code,
              static_cast<std::uint32_t>(DISPLAYD_REPLY_SUCCESS));
    EXPECT_EQ(DrainEvents(g_engines[2], peer_b, events, 4), 1U);
    EXPECT_EQ(events[0].type, static_cast<std::uint8_t>(DISPLAYD_EVENT_BOUNDS_CHANGED));

    auto hide_b = SurfaceRequest(104, DISPLAYD_COMMAND_SET_VISIBLE, surface_b);
    hide_b.visible = 0;
    EXPECT_EQ(ApplySurfaceRequest(g_engines[2], peer_b, hide_b).code,
              static_cast<std::uint32_t>(DISPLAYD_REPLY_SUCCESS));
    EXPECT_EQ(DrainEvents(g_engines[2], peer_b, events, 4), 2U);
    EXPECT_EQ(events[0].type, static_cast<std::uint8_t>(DISPLAYD_EVENT_FOCUS_LOST));
    EXPECT_EQ(events[1].type, static_cast<std::uint8_t>(DISPLAYD_EVENT_VISIBILITY_CHANGED));
    EXPECT_EQ(DrainEvents(g_engines[2], peer_a, events, 4), 1U);
    EXPECT_EQ(events[0].type, static_cast<std::uint8_t>(DISPLAYD_EVENT_FOCUS_GAINED));

    auto destroy_a = SurfaceRequest(3, DISPLAYD_COMMAND_DESTROY_SURFACE, surface_a);
    EXPECT_EQ(ApplySurfaceRequest(g_engines[2], peer_a, destroy_a).code,
              static_cast<std::uint32_t>(DISPLAYD_REPLY_SUCCESS));
    EXPECT_EQ(DrainEvents(g_engines[2], peer_a, events, 4), 2U);
    EXPECT_EQ(events[0].type, static_cast<std::uint8_t>(DISPLAYD_EVENT_FOCUS_LOST));
    EXPECT_EQ(events[1].type, static_cast<std::uint8_t>(DISPLAYD_EVENT_SURFACE_DESTROYED));
    EXPECT_EQ(DisplaydEngineInspectSurface(&g_engines[2], &surface_a, &a_snapshot), DISPLAYD_ENGINE_SURFACE_NOT_FOUND);

    auto stale_destroy = SurfaceRequest(4, DISPLAYD_COMMAND_DESTROY_SURFACE, surface_a);
    EXPECT_EQ(ApplySurfaceRequest(g_engines[2], peer_a, stale_destroy).code,
              static_cast<std::uint32_t>(DISPLAYD_REPLY_INVALID_SURFACE));
}

void TestEventCapacityIsAtomic()
{
    Initialize(g_engines[3]);
    const auto peer = Open(g_engines[3], Peer(30), 1);
    const auto target = CreateSurface(g_engines[3], peer, 1, Rect(1, 1), true);
    for (std::uint64_t request_id = 2; request_id <= 15; ++request_id)
        (void)CreateSurface(g_engines[3], peer, request_id, Rect(static_cast<std::int32_t>(request_id), 2), false);

    DisplaydPeerSnapshot peer_snapshot{};
    EXPECT_EQ(DisplaydEngineInspectPeer(&g_engines[3], &peer, &peer_snapshot), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(peer_snapshot.event_count, DISPLAYD_ENGINE_MAX_EVENTS_PER_PEER);
    DisplaydEngineSnapshot before{};
    DisplaydSurfaceSnapshot surface_before{};
    EXPECT_EQ(DisplaydEngineDescribe(&g_engines[3], &before), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(DisplaydEngineInspectSurface(&g_engines[3], &target, &surface_before), DISPLAYD_ENGINE_OK);

    auto blocked_bounds = SurfaceRequest(16, DISPLAYD_COMMAND_SET_BOUNDS, target);
    blocked_bounds.bounds = Rect(400, 300, 200, 100);
    EXPECT_EQ(ApplySurfaceRequest(g_engines[3], peer, blocked_bounds).code,
              static_cast<std::uint32_t>(DISPLAYD_REPLY_EVENT_QUEUE_FULL));
    DisplaydEngineSnapshot after{};
    DisplaydSurfaceSnapshot surface_after{};
    EXPECT_EQ(DisplaydEngineDescribe(&g_engines[3], &after), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(DisplaydEngineInspectSurface(&g_engines[3], &target, &surface_after), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(after.state_epoch, before.state_epoch);
    EXPECT_EQ(surface_after.bounds.x, surface_before.bounds.x);
    EXPECT_EQ(surface_after.bounds.y, surface_before.bounds.y);
    EXPECT_EQ(surface_after.bounds.width, surface_before.bounds.width);
    EXPECT_EQ(surface_after.bounds.height, surface_before.bounds.height);
    EXPECT_EQ(surface_after.z_rank, surface_before.z_rank);

    EXPECT_EQ(DrainEvents(g_engines[3], peer), DISPLAYD_ENGINE_MAX_EVENTS_PER_PEER);
    auto accepted_bounds = SurfaceRequest(17, DISPLAYD_COMMAND_SET_BOUNDS, target);
    accepted_bounds.bounds = blocked_bounds.bounds;
    EXPECT_EQ(ApplySurfaceRequest(g_engines[3], peer, accepted_bounds).code,
              static_cast<std::uint32_t>(DISPLAYD_REPLY_SUCCESS));
    EXPECT_EQ(DisplaydEngineDescribe(&g_engines[3], &after), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(after.state_epoch, before.state_epoch + 1U);
    EXPECT_EQ(DrainEvents(g_engines[3], peer), 1U);
}

void TestReuseCloseAndTerminalDrain()
{
    Initialize(g_engines[4]);
    const auto identity = Peer(40);
    const auto peer = Open(g_engines[4], identity, 1);
    const auto old_surface = CreateSurface(g_engines[4], peer, 1, Rect(10, 10), true);
    EXPECT_EQ(DrainEvents(g_engines[4], peer), 2U);

    auto destroy = SurfaceRequest(2, DISPLAYD_COMMAND_DESTROY_SURFACE, old_surface);
    EXPECT_EQ(ApplySurfaceRequest(g_engines[4], peer, destroy).code,
              static_cast<std::uint32_t>(DISPLAYD_REPLY_SUCCESS));
    EXPECT_EQ(DrainEvents(g_engines[4], peer), 2U);
    const auto fresh_surface = CreateSurface(g_engines[4], peer, 3, Rect(20, 20), true);
    EXPECT_EQ(fresh_surface.slot, old_surface.slot);
    EXPECT_NE(fresh_surface.generation, old_surface.generation);

    DisplaydSurfaceSnapshot surface_snapshot{};
    EXPECT_EQ(DisplaydEngineInspectSurface(&g_engines[4], &old_surface, &surface_snapshot),
              DISPLAYD_ENGINE_STALE_SURFACE);
    auto stale_destroy = SurfaceRequest(4, DISPLAYD_COMMAND_DESTROY_SURFACE, old_surface);
    EXPECT_EQ(ApplySurfaceRequest(g_engines[4], peer, stale_destroy).code,
              static_cast<std::uint32_t>(DISPLAYD_REPLY_INVALID_SURFACE));

    auto queued_bounds = SurfaceRequest(5, DISPLAYD_COMMAND_SET_BOUNDS, fresh_surface);
    queued_bounds.bounds = Rect(100, 100);
    const auto queued_receipt = Submit(g_engines[4], peer, queued_bounds);
    DisplaydEventPublication abandoned_event{};
    EXPECT_EQ(DisplaydEngineGetNextEvent(&g_engines[4], &peer, &abandoned_event), DISPLAYD_ENGINE_OK);
    DisplaydPeerDrainSummary summary{};
    EXPECT_EQ(DisplaydEngineClosePeer(&g_engines[4], &peer, &summary), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(summary.surfaces_destroyed, 1U);
    EXPECT_EQ(summary.requests_retired, 1U);
    EXPECT_EQ(summary.events_retired, 2U);
    EXPECT_EQ(summary.focus_cleared, 1U);
    EXPECT_EQ(DisplaydEngineCommitEvent(&g_engines[4], &abandoned_event.lease), DISPLAYD_ENGINE_STALE_EVENT);
    DisplaydRequestSnapshot request_snapshot{};
    EXPECT_EQ(DisplaydEngineInspectRequest(&g_engines[4], &queued_receipt, &request_snapshot),
              DISPLAYD_ENGINE_STALE_REPLY);

    const auto replacement = Open(g_engines[4], identity, 10);
    EXPECT_EQ(replacement.slot, peer.slot);
    EXPECT_NE(replacement.generation, peer.generation);
    DisplaydPeerSnapshot peer_snapshot{};
    EXPECT_EQ(DisplaydEngineInspectPeer(&g_engines[4], &peer, &peer_snapshot), DISPLAYD_ENGINE_STALE_PEER);

    Submit(g_engines[4], replacement, Create(10, Rect(1, 1), true));
    (void)Apply(g_engines[4]);
    DisplaydReplyPublication abandoned_reply{};
    DisplaydEventPublication drain_event{};
    EXPECT_EQ(DisplaydEngineGetNextReply(&g_engines[4], &replacement, &abandoned_reply), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(DisplaydEngineGetNextEvent(&g_engines[4], &replacement, &drain_event), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(DisplaydEngineBeginDrain(&g_engines[4]), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(DisplaydEngineBeginDrain(&g_engines[4]), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(DisplaydEngineCommitReply(&g_engines[4], &abandoned_reply.lease), DISPLAYD_ENGINE_STALE_REPLY);
    EXPECT_EQ(DisplaydEngineCommitEvent(&g_engines[4], &drain_event.lease), DISPLAYD_ENGINE_STALE_EVENT);

    DisplaydEngineSnapshot snapshot{};
    EXPECT_EQ(DisplaydEngineDescribe(&g_engines[4], &snapshot), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(snapshot.state, static_cast<std::uint32_t>(DISPLAYD_ENGINE_STATE_DRAINING));
    EXPECT_EQ(snapshot.peer_count, 0U);
    EXPECT_EQ(snapshot.surface_count, 0U);
    EXPECT_EQ(snapshot.request_count, 0U);
    EXPECT_EQ(snapshot.event_count, 0U);
    EXPECT_EQ(DisplaydEngineFinishDrain(&g_engines[4]), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(DisplaydEngineFinishDrain(&g_engines[4]), DISPLAYD_ENGINE_OK);
    DisplaydPeerReceipt rejected{};
    EXPECT_EQ(DisplaydEngineOpenPeer(&g_engines[4], &identity, 20, &rejected), DISPLAYD_ENGINE_CLOSED);
    DisplaydApplyResult no_apply{};
    EXPECT_EQ(DisplaydEngineApplyNext(&g_engines[4], &no_apply), DISPLAYD_ENGINE_CLOSED);
}

void TestGenerationAndSequenceExhaustion()
{
    Initialize(g_engines[5], UINT64_MAX);
    for (std::uint64_t index = 0; index < DISPLAYD_ENGINE_MAX_PEERS; ++index)
    {
        const auto peer = Open(g_engines[5], Peer(100 + index), 1);
        EXPECT_EQ(peer.generation, UINT64_MAX);
        DisplaydPeerDrainSummary summary{};
        EXPECT_EQ(DisplaydEngineClosePeer(&g_engines[5], &peer, &summary), DISPLAYD_ENGINE_OK);
    }
    DisplaydPeerReceipt unavailable{};
    const auto another_identity = Peer(500);
    EXPECT_EQ(DisplaydEngineOpenPeer(&g_engines[5], &another_identity, 1, &unavailable),
              DISPLAYD_ENGINE_GENERATION_EXHAUSTED);

    Initialize(g_engines[6], UINT64_MAX);
    const auto request_peer = Open(g_engines[6], Peer(600), 1);
    for (std::uint64_t request_id = 1; request_id <= DISPLAYD_ENGINE_MAX_REQUESTS; ++request_id)
    {
        (void)Submit(g_engines[6], request_peer, Create(request_id, Rect(1, 1), false));
        DisplaydRequestReceipt cancelled{};
        EXPECT_EQ(DisplaydEngineCancel(&g_engines[6], &request_peer, request_id, &cancelled), DISPLAYD_ENGINE_OK);
        EXPECT_EQ(CommitNextReply(g_engines[6], request_peer).code,
                  static_cast<std::uint32_t>(DISPLAYD_REPLY_CANCELLED));
    }
    DisplaydRequestReceipt exhausted{};
    const auto request_65 = Create(DISPLAYD_ENGINE_MAX_REQUESTS + 1ULL, Rect(1, 1), false);
    EXPECT_EQ(DisplaydEngineSubmit(&g_engines[6], &request_peer, &request_65, &exhausted),
              DISPLAYD_ENGINE_GENERATION_EXHAUSTED);

    Initialize(g_engines[7]);
    const auto sequence_peer = Open(g_engines[7], Peer(700), UINT64_MAX);
    const auto final_request = Create(UINT64_MAX, Rect(1, 1), false);
    (void)Submit(g_engines[7], sequence_peer, final_request);
    DisplaydRequestReceipt cancelled{};
    EXPECT_EQ(DisplaydEngineCancel(&g_engines[7], &sequence_peer, UINT64_MAX, &cancelled), DISPLAYD_ENGINE_OK);
    (void)CommitNextReply(g_engines[7], sequence_peer);
    EXPECT_EQ(DisplaydEngineSubmit(&g_engines[7], &sequence_peer, &final_request, &exhausted),
              DISPLAYD_ENGINE_SEQUENCE_EXHAUSTED);
}

void TestMutationSequenceExhaustion()
{
    Initialize(g_engines[8]);
    const auto epoch_peer = Open(g_engines[8], Peer(800), 1);
    auto* epoch_impl = DisplaydInternalMutable(&g_engines[8]);
    epoch_impl->state_epoch = UINT64_MAX - 1U;
    const auto final_epoch_surface = CreateSurface(g_engines[8], epoch_peer, 1, Rect(1, 1), false);
    EXPECT_TRUE(DisplaydSurfaceIdentityIsCanonical(&final_epoch_surface));
    DisplaydEngineSnapshot epoch_snapshot{};
    EXPECT_EQ(DisplaydEngineDescribe(&g_engines[8], &epoch_snapshot), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(epoch_snapshot.state_epoch, UINT64_MAX);
    EXPECT_EQ(DrainEvents(g_engines[8], epoch_peer), 1U);
    Submit(g_engines[8], epoch_peer, Create(2, Rect(2, 2), false));
    EXPECT_EQ(Apply(g_engines[8]).reply.code, static_cast<std::uint32_t>(DISPLAYD_REPLY_STATE_EPOCH_EXHAUSTED));
    (void)CommitNextReply(g_engines[8], epoch_peer);
    EXPECT_EQ(DisplaydEngineDescribe(&g_engines[8], &epoch_snapshot), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(epoch_snapshot.surface_count, 1U);
    EXPECT_EQ(epoch_snapshot.event_count, 0U);

    Initialize(g_engines[9]);
    const auto event_peer = Open(g_engines[9], Peer(900), 1);
    auto* event_impl = DisplaydInternalMutable(&g_engines[9]);
    event_impl->peers[event_peer.slot].next_event_sequence = UINT64_MAX;
    (void)CreateSurface(g_engines[9], event_peer, 1, Rect(1, 1), false);
    DisplaydEvent final_event{};
    EXPECT_EQ(DrainEvents(g_engines[9], event_peer, &final_event, 1), 1U);
    EXPECT_EQ(final_event.sequence, UINT64_MAX);
    DisplaydEngineSnapshot before{};
    EXPECT_EQ(DisplaydEngineDescribe(&g_engines[9], &before), DISPLAYD_ENGINE_OK);
    Submit(g_engines[9], event_peer, Create(2, Rect(2, 2), false));
    EXPECT_EQ(Apply(g_engines[9]).reply.code, static_cast<std::uint32_t>(DISPLAYD_REPLY_EVENT_SEQUENCE_EXHAUSTED));
    (void)CommitNextReply(g_engines[9], event_peer);
    DisplaydEngineSnapshot after{};
    EXPECT_EQ(DisplaydEngineDescribe(&g_engines[9], &after), DISPLAYD_ENGINE_OK);
    EXPECT_EQ(after.state_epoch, before.state_epoch);
    EXPECT_EQ(after.surface_count, before.surface_count);
    EXPECT_EQ(after.event_count, 0U);
}

} // namespace

int main()
{
    TestInitializationAndIdentity();
    TestRequestOrderingCancellationAndPublication();
    TestSurfaceFocusAndZOrder();
    TestEventCapacityIsAtomic();
    TestReuseCloseAndTerminalDrain();
    TestGenerationAndSequenceExhaustion();
    TestMutationSequenceExhaustion();
    return duetos_host_test::finish_main("displayd_engine");
}
