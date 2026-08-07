// Package confium provides Go bindings for the Confium threshold
// cryptography framework.
//
// This package calls into the Rust crates via cgo. The Rust crates
// are compiled into a static library that gets linked into the Go
// binary at build time. See BUILD.md for setup instructions.
//
// Quickstart:
//
//	package main
//
//	import "github.com/confium/confium-go"
//
//	func main() {
//	    kg, _ := confium.Cmp20Keygen(2, 3)
//	    sig, _ := confium.Cmp20Sign(kg.Shares[:2], 2, []byte("hello"))
//	    fmt.Printf("signature: %x\n", sig)
//	    fmt.Printf("public key: %x\n", kg.PublicKey)
//	}
//
// Cross-binding parity: the share-blob and signature wire formats
// match the Ruby, Python, and Node.js bindings exactly. Files saved
// in one binding load in any other.
package confium

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/lib -lconfium_go -lm -ldl

#include "confium_go.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// KeygenResult holds the output of a CMP20 or GG18 DKG.
type KeygenResult struct {
	// Shares is a slice of opaque share blobs (71 bytes each).
	// Distribute to N parties; each party needs exactly its own blob.
	Shares [][]byte
	// PublicKey is the joint P-256 public key in SEC1 compressed
	// form (33 bytes). Embed in an X.509 SubjectPublicKeyInfo for
	// interoperability with standard PKI.
	PublicKey []byte
}

// Cmp20Keygen runs a non-interactive CMP20 DKG for party_count
// parties at threshold T.
//
// Returns the per-party share blobs and the joint public key. The
// caller is responsible for distributing shares to the appropriate
// parties and persisting them securely (see FileSink in the Ruby
// binding for the JSON envelope format).
func Cmp20Keygen(threshold, partyCount uint32) (*KeygenResult, error) {
	// The C bridge returns a single buffer with a length-prefixed
	// envelope: [4 bytes: share count][N x (4 bytes len + share)]
	// [33 bytes: public key].
	var outLen C.size_t
	var outBuf *C.uint8_t
	rc := C.confium_cmp20_keygen(C.uint32_t(threshold), C.uint32_t(partyCount), &outBuf, &outLen)
	if rc != 0 {
		return nil, confiumError(rc)
	}
	defer C.confium_free(unsafe.Pointer(outBuf))

	raw := C.GoBytes(unsafe.Pointer(outBuf), C.int(outLen))
	return parseKeygenEnvelope(raw)
}

// Cmp20Sign threshold-signs `message` using `shares` (each a blob
// from a previous Cmp20Keygen) at threshold T. Returns the 64-byte
// `(r, s)` ECDSA-P256 signature.
//
// Verify under any standard P-256 verifier (Go's crypto/ecdsa,
// OpenSSL, BouncyCastle, Node's crypto) — the signature is a normal
// ECDSA-P256 signature, just one whose private key was threshold-shared.
func Cmp20Sign(shares [][]byte, threshold uint32, message []byte) ([]byte, error) {
	// Flatten shares into a single buffer for the C bridge.
	var flat []byte
	for _, s := range shares {
		lenBytes := []byte{
			byte(len(s) >> 24), byte(len(s) >> 16),
			byte(len(s) >> 8), byte(len(s)),
		}
		flat = append(flat, lenBytes...)
		flat = append(flat, s...)
	}

	var outLen C.size_t
	var outBuf *C.uint8_t
	rc := C.confium_cmp20_sign(
		(*C.uint8_t)(unsafe.Pointer(&flat[0])),
		C.size_t(len(flat)),
		C.uint32_t(len(shares)),
		C.uint32_t(threshold),
		(*C.uint8_t)(unsafe.Pointer(&message[0])),
		C.size_t(len(message)),
		&outBuf,
		&outLen,
	)
	if rc != 0 {
		return nil, confiumError(rc)
	}
	defer C.confium_free(unsafe.Pointer(outBuf))

	return C.GoBytes(unsafe.Pointer(outBuf), C.int(outLen)), nil
}

// Gg18Keygen runs a GG18 DKG. Same shape as Cmp20Keygen; prefer
// Cmp20Keygen for new deployments.
func Gg18Keygen(threshold, partyCount uint32) (*KeygenResult, error) {
	var outLen C.size_t
	var outBuf *C.uint8_t
	rc := C.confium_gg18_keygen(C.uint32_t(threshold), C.uint32_t(partyCount), &outBuf, &outLen)
	if rc != 0 {
		return nil, confiumError(rc)
	}
	defer C.confium_free(unsafe.Pointer(outBuf))

	raw := C.GoBytes(unsafe.Pointer(outBuf), C.int(outLen))
	return parseKeygenEnvelope(raw)
}

// Gg18Sign threshold-signs `message` using `shares` at threshold T.
func Gg18Sign(shares [][]byte, threshold uint32, message []byte) ([]byte, error) {
	var flat []byte
	for _, s := range shares {
		lenBytes := []byte{
			byte(len(s) >> 24), byte(len(s) >> 16),
			byte(len(s) >> 8), byte(len(s)),
		}
		flat = append(flat, lenBytes...)
		flat = append(flat, s...)
	}

	var outLen C.size_t
	var outBuf *C.uint8_t
	rc := C.confium_gg18_sign(
		(*C.uint8_t)(unsafe.Pointer(&flat[0])),
		C.size_t(len(flat)),
		C.uint32_t(len(shares)),
		C.uint32_t(threshold),
		(*C.uint8_t)(unsafe.Pointer(&message[0])),
		C.size_t(len(message)),
		&outBuf,
		&outLen,
	)
	if rc != 0 {
		return nil, confiumError(rc)
	}
	defer C.confium_free(unsafe.Pointer(outBuf))

	return C.GoBytes(unsafe.Pointer(outBuf), C.int(outLen)), nil
}

// Version returns the Go binding version.
func Version() string {
	return "0.1.0"
}

// --- helpers ---

func parseKeygenEnvelope(raw []byte) (*KeygenResult, error) {
	if len(raw) < 4 {
		return nil, errors.New("confium: keygen envelope too short")
	}
	shareCount := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
	offset := 4
	shares := make([][]byte, 0, shareCount)
	for i := uint32(0); i < shareCount; i++ {
		if offset+4 > len(raw) {
			return nil, errors.New("confium: share length truncated")
		}
		ln := uint32(raw[offset])<<24 | uint32(raw[offset+1])<<16 | uint32(raw[offset+2])<<8 | uint32(raw[offset+3])
		offset += 4
		if offset+int(ln) > len(raw) {
			return nil, errors.New("confium: share body truncated")
		}
		share := make([]byte, ln)
		copy(share, raw[offset:offset+int(ln)])
		offset += int(ln)
		shares = append(shares, share)
	}
	if offset+33 > len(raw) {
		return nil, errors.New("confium: public key truncated")
	}
	pk := make([]byte, 33)
	copy(pk, raw[offset:offset+33])

	return &KeygenResult{Shares: shares, PublicKey: pk}, nil
}

func confiumError(rc C.int) error {
	switch rc {
	case -1:
		return errors.New("confium: threshold exceeds party count")
	case -2:
		return errors.New("confium: corrupt share blob")
	case -3:
		return errors.New("confium: protocol error (see stderr)")
	default:
		return errors.New("confium: unknown error")
	}
}
