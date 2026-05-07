// DuetFS journal — atomic-commit log against torn writes (v5).
//
// Layout (lives at JOURNAL_LBA, JOURNAL_BLOCKS blocks long):
//
//   block 0    descriptor — magic, state, txn_id, op_count, per-op
//              (target_lba, payload_crc) pairs, descriptor CRC
//   block 1..N payload slots — the bytes destined for target_lba
//
// State machine (all transitions cross a single block-write barrier
// — the descriptor block — so a torn write either retains the old
// descriptor (no journal) or persists the new one (full journal)):
//
//   1. Stage: caller wants to write payloads P1..Pk to target LBAs
//      T1..Tk atomically. We write each Pi into journal block i+1.
//      The descriptor still has state == EMPTY, so a crash here
//      replays nothing and target LBAs keep their old contents.
//
//   2. Commit: write descriptor with state == COMMITTED, op_count = k,
//      target+CRC pairs, and a CRC over the descriptor itself. A
//      crash *after* this write means replay sees state == COMMITTED
//      and finishes the apply.
//
//   3. Apply: copy each payload from its journal slot to its target
//      LBA. Idempotent — a half-finished apply replays cleanly.
//
//   4. Clear: write descriptor with state == EMPTY. Marks the txn
//      done; subsequent mounts skip replay.
//
// Replay (run on every Fs::open):
//
//   - Read descriptor. If magic doesn't match, treat as EMPTY.
//   - If state == COMMITTED and descriptor CRC verifies:
//       For each op, verify the journal slot's CRC against the
//       descriptor's stored payload_crc. If any mismatch, abort
//       (the journal itself is torn — apply nothing, leave the
//       descriptor as COMMITTED — fsck flags + repairs).
//       Otherwise copy each slot to its target and clear.
//   - Else: clear if state != EMPTY (sanitises a spurious magic).
//
// Bounds:
//   - MAX_JOURNAL_OPS == JOURNAL_BLOCKS - 1. Caller batches at most
//     this many writes per txn; larger batches split into multiple
//     txns and lose the cross-txn atomicity guarantee (acceptable
//     for v5 — every internal caller writes <= 1 metadata block per
//     mutation).

use crate::block_dev::BlockDevice;
use crate::crc32::crc32;
use crate::format::{
    BLOCK_SIZE, JOURNAL_BLOCKS, JOURNAL_DESCRIPTOR_MAGIC, JOURNAL_STATE_COMMITTED,
    JOURNAL_STATE_EMPTY, MAX_JOURNAL_OPS,
};
use crate::fs::{FsError, FsResult};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct JournalDescriptor
{
    pub magic: u32,
    pub state: u32,
    pub txn_id: u32,
    pub op_count: u32,
    pub descriptor_crc: u32, // CRC over the descriptor with this field zeroed
    pub reserved: [u32; 3],
    pub targets: [u32; MAX_JOURNAL_OPS],
    pub payload_crcs: [u32; MAX_JOURNAL_OPS],
}

const _: () = assert!(core::mem::size_of::<JournalDescriptor>() <= BLOCK_SIZE);

impl JournalDescriptor
{
    pub const fn empty() -> Self
    {
        Self {
            magic: JOURNAL_DESCRIPTOR_MAGIC,
            state: JOURNAL_STATE_EMPTY,
            txn_id: 0,
            op_count: 0,
            descriptor_crc: 0,
            reserved: [0; 3],
            targets: [0; MAX_JOURNAL_OPS],
            payload_crcs: [0; MAX_JOURNAL_OPS],
        }
    }
}

fn read_descriptor<D: BlockDevice + ?Sized>(dev: &mut D, jlba: u32) -> FsResult<JournalDescriptor>
{
    let mut block = [0u8; BLOCK_SIZE];
    dev.read_block(jlba, &mut block).map_err(|_| FsError::Io)?;
    let mut d = JournalDescriptor::empty();
    let raw = unsafe {
        core::slice::from_raw_parts_mut(
            (&mut d) as *mut JournalDescriptor as *mut u8,
            core::mem::size_of::<JournalDescriptor>(),
        )
    };
    raw.copy_from_slice(&block[..core::mem::size_of::<JournalDescriptor>()]);
    Ok(d)
}

fn write_descriptor<D: BlockDevice + ?Sized>(
    dev: &mut D, jlba: u32, d: &JournalDescriptor,
) -> FsResult<()>
{
    let mut block = [0u8; BLOCK_SIZE];
    let raw = unsafe {
        core::slice::from_raw_parts(
            (d as *const JournalDescriptor) as *const u8,
            core::mem::size_of::<JournalDescriptor>(),
        )
    };
    block[..raw.len()].copy_from_slice(raw);
    dev.write_block(jlba, &block).map_err(|_| FsError::Io)
}

fn compute_descriptor_crc(d: &JournalDescriptor) -> u32
{
    let mut copy = *d;
    copy.descriptor_crc = 0;
    let raw = unsafe {
        core::slice::from_raw_parts(
            (&copy as *const JournalDescriptor) as *const u8,
            core::mem::size_of::<JournalDescriptor>(),
        )
    };
    crc32(raw)
}

/// Apply `ops` atomically through the journal at `jlba` (length
/// `JOURNAL_BLOCKS`). On a successful return every target LBA holds
/// its new payload. On error, target LBAs may be in any state but
/// `replay` on next mount restores invariants.
pub fn apply<D: BlockDevice + ?Sized>(
    dev: &mut D, jlba: u32, txn_id: u32, ops: &[(u32, &[u8])],
) -> FsResult<()>
{
    if ops.is_empty()
    {
        return Ok(());
    }
    if ops.len() > MAX_JOURNAL_OPS
    {
        return Err(FsError::Invalid);
    }
    // 1. Stage payloads to journal slots.
    let mut targets = [0u32; MAX_JOURNAL_OPS];
    let mut crcs = [0u32; MAX_JOURNAL_OPS];
    for (i, (target, payload)) in ops.iter().enumerate()
    {
        if payload.len() != BLOCK_SIZE
        {
            return Err(FsError::Invalid);
        }
        let slot_lba = jlba + 1 + i as u32;
        // Safety check: slot must fit inside the reserved journal range.
        if slot_lba >= jlba + JOURNAL_BLOCKS
        {
            return Err(FsError::Invalid);
        }
        dev.write_block(slot_lba, payload).map_err(|_| FsError::Io)?;
        targets[i] = *target;
        crcs[i] = crc32(payload);
    }
    // 2. Commit: write descriptor with state == COMMITTED.
    let mut d = JournalDescriptor::empty();
    d.state = JOURNAL_STATE_COMMITTED;
    d.txn_id = txn_id;
    d.op_count = ops.len() as u32;
    d.targets = targets;
    d.payload_crcs = crcs;
    d.descriptor_crc = compute_descriptor_crc(&d);
    write_descriptor(dev, jlba, &d)?;
    // 3. Apply payloads to their target LBAs.
    let mut buf = [0u8; BLOCK_SIZE];
    for i in 0..ops.len()
    {
        let slot_lba = jlba + 1 + i as u32;
        dev.read_block(slot_lba, &mut buf).map_err(|_| FsError::Io)?;
        dev.write_block(targets[i], &buf).map_err(|_| FsError::Io)?;
    }
    // 4. Clear.
    let cleared = JournalDescriptor::empty();
    write_descriptor(dev, jlba, &cleared)?;
    Ok(())
}

/// Replay any committed-but-unfinished transaction. Called from
/// Fs::open. Returns the next txn_id to issue (one past the
/// committed one, or 1 if the journal was empty).
pub fn replay<D: BlockDevice + ?Sized>(dev: &mut D, jlba: u32) -> FsResult<u32>
{
    let d = read_descriptor(dev, jlba)?;
    if d.magic != JOURNAL_DESCRIPTOR_MAGIC || d.state != JOURNAL_STATE_COMMITTED
    {
        // EMPTY or unrecognised — sanitise to EMPTY and pick a txn_id
        // that's monotone given what's on disk.
        let next = d.txn_id.saturating_add(1).max(1);
        let cleared = JournalDescriptor::empty();
        // Only rewrite if the on-disk block isn't already a clean EMPTY
        // descriptor — saves a write on the common path.
        if d.magic != JOURNAL_DESCRIPTOR_MAGIC || d.state != JOURNAL_STATE_EMPTY
        {
            write_descriptor(dev, jlba, &cleared)?;
        }
        return Ok(next);
    }
    // COMMITTED — verify descriptor CRC.
    let want = d.descriptor_crc;
    let got = compute_descriptor_crc(&d);
    if want != got
    {
        // Torn descriptor: leave alone for fsck. Don't clear — clearing
        // would lose the only evidence the txn started.
        return Err(FsError::Corrupt);
    }
    if (d.op_count as usize) > MAX_JOURNAL_OPS
    {
        return Err(FsError::Corrupt);
    }
    // Verify each payload's CRC against the descriptor's stored CRC.
    let mut buf = [0u8; BLOCK_SIZE];
    for i in 0..d.op_count as usize
    {
        let slot_lba = jlba + 1 + i as u32;
        dev.read_block(slot_lba, &mut buf).map_err(|_| FsError::Io)?;
        if crc32(&buf) != d.payload_crcs[i]
        {
            // Torn payload — abort replay; leave descriptor as
            // COMMITTED so fsck (or a subsequent mount with intact
            // payloads) can finish the apply.
            return Err(FsError::Corrupt);
        }
    }
    // Apply.
    for i in 0..d.op_count as usize
    {
        let slot_lba = jlba + 1 + i as u32;
        dev.read_block(slot_lba, &mut buf).map_err(|_| FsError::Io)?;
        dev.write_block(d.targets[i], &buf).map_err(|_| FsError::Io)?;
    }
    // Clear.
    let cleared = JournalDescriptor::empty();
    write_descriptor(dev, jlba, &cleared)?;
    Ok(d.txn_id.saturating_add(1).max(1))
}

/// Read the on-disk descriptor without replaying. Used by fsck and
/// the self-test to inspect journal state.
#[allow(dead_code)]
pub fn peek_descriptor<D: BlockDevice + ?Sized>(
    dev: &mut D, jlba: u32,
) -> FsResult<JournalDescriptor>
{
    read_descriptor(dev, jlba)
}

/// Test-only: stage payloads + write a COMMITTED descriptor, but
/// stop BEFORE applying to target LBAs. Mimics a power loss between
/// "journal commit fsync'd" and "apply finished" — the next
/// `Fs::open` should replay and finish the apply. Not used by any
/// production path.
pub fn inject_committed_for_test<D: BlockDevice + ?Sized>(
    dev: &mut D, jlba: u32, txn_id: u32, ops: &[(u32, &[u8])],
) -> FsResult<()>
{
    if ops.is_empty() || ops.len() > MAX_JOURNAL_OPS
    {
        return Err(FsError::Invalid);
    }
    let mut targets = [0u32; MAX_JOURNAL_OPS];
    let mut crcs = [0u32; MAX_JOURNAL_OPS];
    for (i, (target, payload)) in ops.iter().enumerate()
    {
        if payload.len() != BLOCK_SIZE
        {
            return Err(FsError::Invalid);
        }
        let slot_lba = jlba + 1 + i as u32;
        if slot_lba >= jlba + JOURNAL_BLOCKS
        {
            return Err(FsError::Invalid);
        }
        dev.write_block(slot_lba, payload).map_err(|_| FsError::Io)?;
        targets[i] = *target;
        crcs[i] = crc32(payload);
    }
    let mut d = JournalDescriptor::empty();
    d.state = JOURNAL_STATE_COMMITTED;
    d.txn_id = txn_id;
    d.op_count = ops.len() as u32;
    d.targets = targets;
    d.payload_crcs = crcs;
    d.descriptor_crc = compute_descriptor_crc(&d);
    write_descriptor(dev, jlba, &d)
}
