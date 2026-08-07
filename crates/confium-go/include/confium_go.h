// Bridge header: Go → C → Rust.
//
// These declarations are the cgo-side interface. The matching Rust
// implementations live in crates/confium-go-bridge/src/lib.rs and
// are compiled into libconfium_go.a, which the Go linker pulls in
// via the LDFLAGS pragma in confium.go.

#ifndef CONFIUM_GO_H
#define CONFIUM_GO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Run a CMP20 DKG for `threshold` of `party_count` parties.
// On success, returns 0 and writes a length-prefixed envelope to
// *out_buf / *out_len. The envelope layout:
//
//   [u32 BE share count]
//   for each share: [u32 BE length][share bytes]
//   [33 bytes: joint public key SEC1 compressed]
//
// Caller must free *out_buf via confium_free().
int32_t confium_cmp20_keygen(uint32_t threshold,
                              uint32_t party_count,
                              uint8_t** out_buf,
                              size_t* out_len);

// Threshold-sign `message` using the supplied `shares_flat` buffer
// (length-prefixed share blobs concatenated). Returns 0 on success
// and writes a 64-byte (r || s) signature to *out_buf.
int32_t confium_cmp20_sign(const uint8_t* shares_flat,
                            size_t shares_flat_len,
                            uint32_t share_count,
                            uint32_t threshold,
                            const uint8_t* message,
                            size_t message_len,
                            uint8_t** out_buf,
                            size_t* out_len);

// GG18 variants — identical signatures.
int32_t confium_gg18_keygen(uint32_t threshold,
                             uint32_t party_count,
                             uint8_t** out_buf,
                             size_t* out_len);

int32_t confium_gg18_sign(const uint8_t* shares_flat,
                           size_t shares_flat_len,
                           uint32_t share_count,
                           uint32_t threshold,
                           const uint8_t* message,
                           size_t message_len,
                           uint8_t** out_buf,
                           size_t* out_len);

// Free a buffer allocated by any of the confium_* functions.
void confium_free(void* ptr);

#ifdef __cplusplus
}
#endif

#endif  // CONFIUM_GO_H
