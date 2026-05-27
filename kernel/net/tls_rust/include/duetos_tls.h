#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // Mirrors `DuetosTlsRecordView` in
    // kernel/net/tls_rust/src/lib.rs. C++ tls.cpp copies the
    // fields into the existing `duetos::net::tls::RecordView`
    // declared in tls.h — the two shapes are equivalent but the
    // C++ struct stays as the public API so callers don't pick up
    // a Rust-name field.
    typedef struct DuetosTlsRecordView
    {
        uint8_t content_type;
        uint16_t version;
        uint16_t length;
        const uint8_t* payload;
    } DuetosTlsRecordView;

    typedef struct DuetosTlsHandshakeView
    {
        uint8_t kind;
        uint32_t length;
        const uint8_t* body;
    } DuetosTlsHandshakeView;

    bool duetos_tls_peek_record(const uint8_t* buf, uint32_t len, DuetosTlsRecordView* out);
    bool duetos_tls_peek_handshake(const uint8_t* buf, uint32_t len, DuetosTlsHandshakeView* out);
    bool duetos_tls_parse_server_hello(const uint8_t* body, uint32_t len, uint8_t server_random[32],
                                       uint16_t* out_cipher);
    bool duetos_tls_parse_certificate_leaf(const uint8_t* body, uint32_t len, const uint8_t** out_leaf_der,
                                           uint32_t* out_leaf_len);
    bool duetos_tls_parse_server_hello_done(const uint8_t* body, uint32_t len);

#ifdef __cplusplus
}
#endif
