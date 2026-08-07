# `confium-go` — Go bindings for Confium

[![Go Reference](https://pkg.go.dev/badge/github.com/confium/confium-go.svg)](https://pkg.go.dev/github.com/confium/confium-go)
[![license](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)

Go bindings for the [Confium](https://www.confium.org/) threshold
cryptography framework. Opens Confium to the cloud-native ecosystem
— Kubernetes operators, Terraform providers, Docker plugins, and
every CNCF project are written in Go.

## Status: scaffold

This package is a **scaffold** — the Go API surface and cgo
plumbing are defined, but the C bridge that translates Go calls into
Rust calls (via `extern "C"` shims in `crates/confium-go-bridge/`)
is not yet implemented. The scaffold lets Go consumers design
integrations against a stable API before the bridge ships.

When the bridge lands (tracked as TODO 098), every Go program that
imports this package will get a working binding with no API changes.

## Why Go?

- **Cloud-native**: Kubernetes, Docker, Istio, Linkerd, Terraform,
  Pulumi — all the major cloud-native projects are Go. A Go binding
  lets Confium plug into all of them.
- **Single static binary**: Go compiles to a single static binary,
  including the Rust crates via cgo. No runtime dependencies.
- **Stdlib crypto**: Go's `crypto/ecdsa` is widely deployed. Confium
  signatures verify under stdlib with zero glue code.

## API surface

```go
package main

import (
    "fmt"
    "github.com/confium/confium-go"
)

func main() {
    // 1. Threshold keygen (2-of-3 CMP20).
    kg, err := confium.Cmp20Keygen(2, 3)
    if err != nil { panic(err) }
    fmt.Printf("public key: %x\n", kg.PublicKey)

    // 2. Sign with any 2 of the 3 shares.
    sig, err := confium.Cmp20Sign(kg.Shares[:2], 2, []byte("hello"))
    if err != nil { panic(err) }
    fmt.Printf("signature: %x\n", sig)

    // 3. Verify under Go's stdlib crypto/ecdsa.
    verifyUnderStdlib(kg.PublicKey, []byte("hello"), sig)
}
```

## Cross-binding parity

The wire formats (share blobs, signatures, public keys) match the
Ruby, Python, and Node.js bindings exactly. Files saved in one
binding load in any other. See
[`ShareFile`](https://github.com/confium/confium-ruby/blob/main/lib/confium/tc/share_file.rb)
for the JSON envelope.

## Build (when the bridge ships)

```sh
go get github.com/confium/confium-go
```

The package ships with a `cgo` build directive that handles the
linking automatically. Pre-built static libraries for Linux x86_64,
macOS arm64, and Windows x86_64 are bundled in `lib/`.

## License

BSD-2-Clause, same as the rest of Confium.

## See also

- [Confium project](https://www.confium.org/)
- [Go package reference](https://pkg.go.dev/github.com/confium/confium-go)
- [Ruby binding](https://github.com/confium/confium-ruby)
- [Python binding](https://pypi.org/project/confium/)
- [Node.js binding](https://www.npmjs.com/package/@confium/confium-node)
