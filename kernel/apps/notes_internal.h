#pragma once

#include "util/types.h"

/*
 * Notes app — private detail surface shared between notes.cpp
 * (input + draw + cursor + the legacy NotesSelfTest) and
 * notes_persist.cpp (FAT32 save / load + the persist self-
 * test).
 *
 * Not part of the public API. Outside the kernel/apps/notes*
 * translation units, callers go through notes.h.
 */

namespace duetos::apps::notes::detail
{

constexpr duetos::u32 kBufCap = 4096;

// Live document state. Defined in notes.cpp; persistence
// reads / writes via these symbols.
extern char g_buf[kBufCap];
extern duetos::u32 g_len;
extern duetos::u32 g_cursor;

// Modified-since-last-save indicator. Set true on every
// mutation primitive (Insert / Delete / Backspace), cleared
// on a successful Save / Load round-trip. Drives the "*MOD"
// flag in the status footer + lets a future "save before
// closing" prompt know whether the buffer needs persisting.
extern bool g_dirty;

// Filename used by NotesSave / NotesLoad on the FAT32 root
// volume. 8.3 form so v0 doesn't need LFN emission. Defined
// in notes.cpp.
extern const char kSaveFile[];

// Insert one character at the cursor, shifting the tail
// right by one. No byte-class filtering — callers vet input.
// Returns false if the buffer is full.
bool InsertAtCursor(char c);

} // namespace duetos::apps::notes::detail
