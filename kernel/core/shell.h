#pragma once

#include "types.h"

/*
 * CustomOS shell — v0.
 *
 * A minimal Linux/macOS-flavoured command prompt on top of the
 * framebuffer console. Accepts printable chars into a line-edit
 * buffer, backspace to rub out, Enter to submit. Dispatches the
 * submitted line to a small built-in command table. Commands:
 *
 *   help      — list available commands
 *   about     — project banner
 *   version   — CustomOS version tag
 *   clear     — wipe the console and show a fresh prompt
 *   uptime    — seconds since the scheduler came online
 *   date      — current wall time + date from the CMOS RTC
 *   windows   — list every registered window + alive flag
 *   echo ...  — print the remainder of the line
 *
 * Everything else prints "command not found: <first token>".
 *
 * Scope limits:
 *   - Single global line buffer (64 chars). No multi-line
 *     editing, no cursor navigation inside the line, no
 *     history (arrow-up recall).
 *   - No argv tokenisation. Commands see the raw string after
 *     the first word; `echo` prints it verbatim.
 *   - No piping / redirection / environment. This is the
 *     smallest thing that reads as a shell.
 *   - Output goes to the framebuffer console via ConsoleWrite.
 *     Serial gets a copy because the klog tee is established.
 *   - Not thread-safe. The kbd reader is the single caller.
 *
 * Context: kernel. Called from the keyboard reader task.
 */

namespace customos::core
{

/// Print the welcome banner + first prompt. Called once after
/// ConsoleInit + ShellInit is ready to accept input.
void ShellInit();

/// Feed a printable ASCII character. Echoes to the console and
/// appends to the edit buffer if it fits.
void ShellFeedChar(char c);

/// Handle the Backspace key — remove the last character from
/// the edit buffer and back up the console's cursor.
void ShellBackspace();

/// Handle the Enter key — terminate the buffer, dispatch to the
/// command table, print output, reset the buffer, show a fresh
/// prompt.
void ShellSubmit();

/// Recall the previous history entry into the edit buffer,
/// rewriting the visible line to match. No-op at the oldest
/// entry or when history is empty. Wired to Up arrow.
void ShellHistoryPrev();

/// Move forward through history (towards the live prompt).
/// Past the newest entry, clears the line. Wired to Down arrow.
void ShellHistoryNext();

/// Tab completion: if the current edit buffer has a unique
/// command-name prefix among the built-ins, extend the line to
/// the full name + a trailing space. Ambiguous prefix prints
/// the list of candidates beneath the prompt then redraws the
/// prompt with the partial. Empty buffer is a no-op.
void ShellTabComplete();

} // namespace customos::core
