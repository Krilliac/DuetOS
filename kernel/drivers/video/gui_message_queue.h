#pragma once

#include "util/types.h"

/*
 * DuetOS -- task-owned GUI message queues.
 *
 * The compositor owns window identity; this module owns delivery order.  A
 * queue is identified only by the immutable scheduler ids {pid, tid}.  It
 * never stores a Task pointer, so scheduler teardown cannot leave a borrowed
 * lifetime in the GUI subsystem.
 *
 * Receive is a two-step transaction:
 *
 *   GuiMessageSnapshot -> copy to user with no queue lock held
 *                      -> GuiMessageCommit
 *
 * Commit checks the queue mutation epoch, exact head ticket, and selected
 * message ticket.  A failed user copy performs no commit.  A competing consumer that
 * wins first makes the stale commit fail, and the syscall retries from a new
 * snapshot.  This is what prevents failed copies and sibling pumps from
 * silently dropping or reordering messages.
 */

namespace duetos::drivers::video
{

inline constexpr u32 kGuiTaskQueueCapacity = 64;
inline constexpr u32 kGuiTaskQueueDepth = 64;

struct WindowMsg
{
    u32 hwnd;    // positive generation-tagged HWND, or 0 for a thread message
    u32 message; // WM_KEYDOWN / WM_CHAR / WM_CLOSE / WM_QUIT / ...
    u64 wparam;
    u64 lparam;
};

struct GuiMessageClaim
{
    WindowMsg message;
    u64 owner_pid;
    u64 owner_tid;
    u64 head_ticket;
    u64 message_ticket;
    u64 queue_epoch;
    u32 queue_slot;
    bool valid;
};

enum class GuiMessageProbeResult : u8
{
    Message,
    Empty,
    Gone,
};

/// Opaque queue-state token returned by GuiMessageProbeQueue. Callers may
/// retain and pass it back to GuiMessageProbeTokenCurrent, but must not infer
/// slot or epoch layout from the words.
struct GuiMessageProbeToken
{
    u64 opaque[2];
};

/// Ensure a queue exists for an immutable task identity.  The queue remains
/// owned by that identity until GuiMessageReapTask/Process tears it down.
/// [any task, IRQ-safe, thread-safe]
bool GuiMessageEnsureQueue(u64 pid, u64 tid);

/// Append to an already-established task queue without loss. A missing or full
/// queue returns false; posting never creates a queue and never evicts an older
/// message. Requiring GuiMessageEnsureQueue first makes task reap terminal: a
/// sender that raced teardown cannot resurrect the dead {pid, tid} afterward.
/// [any task, IRQ-safe, thread-safe]
bool GuiMessagePost(u64 pid, u64 tid, const WindowMsg& message);

/// Probe an established task queue without conflating "currently empty" with
/// "reaped/gone". Message returns a transactional claim, Empty returns only a
/// token, and Gone zeroes every non-null output. The per-slot token changes on
/// every queue mutation and never resets across slot reuse.
/// [any task, IRQ-safe, thread-safe]
GuiMessageProbeResult GuiMessageProbeQueue(u64 pid, u64 tid, u32 hwnd_filter, GuiMessageClaim* claim_out,
                                           GuiMessageProbeToken* token_out);

/// True only while `token` still names the same active {pid,tid} queue at the
/// exact mutation epoch observed by GuiMessageProbeQueue. Retained for queue
/// transaction tests and non-blocking clients; GetMessage uses the global
/// message-event sequence now that the scheduler can compare and enqueue
/// atomically.
/// [any task, IRQ-safe, thread-safe]
bool GuiMessageProbeTokenCurrent(u64 pid, u64 tid, const GuiMessageProbeToken& token);

/// Snapshot the first message matching `hwnd_filter` (0 means no filter).
/// No lock remains held on return.
/// [any task, IRQ-safe, thread-safe]
bool GuiMessageSnapshot(u64 pid, u64 tid, u32 hwnd_filter, GuiMessageClaim* claim_out);

/// Validate a prior snapshot and optionally remove that exact message while
/// preserving the relative order of all other entries.  Returns false when a
/// peer consumer or queue reap invalidated the claim.
/// [any task, IRQ-safe, thread-safe]
bool GuiMessageCommit(const GuiMessageClaim& claim, bool remove);

/// Remove every queued entry for one destroyed HWND, preserving the remaining
/// task-queue order. The queue epoch advances even when zero entries match so
/// a waiter cannot mistake HWND invalidation for unchanged empty state.
/// [any task, IRQ-safe, thread-safe]
u32 GuiMessagePurgeWindow(u64 pid, u64 tid, u32 hwnd);

/// Drain and unbind one task queue.  Returns the number of discarded entries.
/// [task teardown, IRQ-safe, thread-safe]
u32 GuiMessageReapTask(u64 pid, u64 tid);

/// Process-final fallback: drain every queue owned by `pid`.
/// [process teardown, IRQ-safe, thread-safe]
u32 GuiMessageReapProcess(u64 pid);

/// Focused boot regression for failed-copy preservation, competing-consumer
/// commit rejection, filter ordering, full-queue refusal, empty-token
/// invalidation by post/zero-match purge/reap, epoch overflow refusal, and
/// reap/reuse ABA.
void GuiMessageQueueSelfTest();
bool GuiMessageQueueSelfTestPassed();

} // namespace duetos::drivers::video
