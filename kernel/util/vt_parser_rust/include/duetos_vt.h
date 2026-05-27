#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // Maximum numeric parameters per CSI sequence. Matches kMaxParams
    // in kernel/util/vt_parser.h.
    enum
    {
        DUETOS_VT_MAX_PARAMS = 16,
        DUETOS_VT_MAX_OSC_LEN = 256,
    };

    // Parser state value. The C++ side mirrors this enum in
    // kernel/util/vt_parser.h::State for binary compatibility.
    enum DuetosVtState
    {
        DUETOS_VT_STATE_GROUND = 0,
        DUETOS_VT_STATE_ESCAPE = 1,
        DUETOS_VT_STATE_CSI_ENTRY = 2,
        DUETOS_VT_STATE_CSI_PARAM = 3,
        DUETOS_VT_STATE_OSC_STRING = 4,
        DUETOS_VT_STATE_OSC_ESCAPE = 5,
    };

    // Callbacks invoked by the parser. All function pointers may be
    // NULL — the parser falls back to silently dropping the event.
    // Cookie is opaque to the parser and passed back to every
    // callback. Callbacks run synchronously from within
    // `duetos_vt_parser_feed`; callers must not re-enter the parser
    // from inside a callback.
    typedef struct DuetosVtCallbacks
    {
        void* cookie;
        void (*print)(void* cookie, uint32_t cp);
        void (*execute)(void* cookie, uint8_t ctrl);
        void (*csi)(void* cookie, char final_byte, char private_marker, const uint16_t* params, uint32_t nparams);
        void (*osc)(void* cookie, uint32_t cmd, const char* str, uint32_t str_len);
    } DuetosVtCallbacks;

    // Parser state. Treat as opaque — the field layout matches the
    // C++ `Parser` struct in vt_parser.h for binary compatibility,
    // but C++ callers should use the public ParserInit/Reset/Feed
    // accessors instead of poking the fields directly.
    typedef struct DuetosVtParser
    {
        uint8_t state;
        uint8_t utf8_bytes_remaining;
        uint8_t utf8_seq_len;
        uint8_t _pad0;

        uint32_t utf8_accum_cp;
        uint8_t utf8_buf[4];

        uint16_t params[DUETOS_VT_MAX_PARAMS];
        uint32_t nparams;
        uint32_t current_param;
        bool current_param_set;
        bool overflow_params;
        char private_marker;
        uint8_t _pad1;

        char osc_buf[DUETOS_VT_MAX_OSC_LEN];
        uint32_t osc_len;
        bool osc_truncated;
        uint8_t _pad2[3];

        DuetosVtCallbacks cb;
    } DuetosVtParser;

    // Initialize the parser, installing `cb` and resetting every
    // state field.
    void duetos_vt_parser_init(DuetosVtParser* p, const DuetosVtCallbacks* cb);

    // Reset state without re-installing callbacks.
    void duetos_vt_parser_reset(DuetosVtParser* p);

    // Feed `len` bytes to the parser. Drives callbacks synchronously.
    // Returns the number of bytes consumed (always equal to `len`).
    uint32_t duetos_vt_parser_feed(DuetosVtParser* p, const uint8_t* bytes, uint32_t len);

#ifdef __cplusplus
}
#endif
