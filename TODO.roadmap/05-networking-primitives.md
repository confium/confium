# 05 — Networking Primitives

## Why Confium provides networking

Slide 4 of the NIST deck is explicit: Confium "supplies primitives for networking" so cryptographers "focus on what's important." Every threshold scheme is a multi-party protocol — without a transport, plugin authors each roll their own socket code. That's wasted effort, inconsistent security, and a barrier to entry.

Confium supplies a Network abstraction. Plugin authors request a transport by URL; Confium handles the bytes.

## Layered design

```
┌────────────────────────────────────────────┐
│         Plugin (tc-signature, etc.)         │
└────────────────────────────────────────────┘
                       │
              cfmp_net_* FFI
                       │
┌────────────────────────────────────────────┐
│           Network API (Rust)               │
│   trait Transport { connect, send, recv }  │
└────────────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
   in-process      tcp/quic       websocket
   (loopback)      (LAN/WAN)      (cloud)
```

## Transport FFI

```c
uint32_t cfmp_net_open(
    FFINetEndpoint **out,
    const char *url,                    // "tcp://1.2.3.4:443", "quic://...", "ws://...", "inproc://session-42"
    const Option *opts);                // TLS cert, auth, etc.

uint32_t cfmp_net_send(
    FFINetEndpoint *ep,
    const uint8_t *data, uint32_t len);

uint32_t cfmp_net_recv(
    FFINetEndpoint *ep,
    uint8_t *out, uint32_t out_max, uint32_t *out_len);

uint32_t cfmp_net_close(FFINetEndpoint *ep);

// For server-side TC plugins (often one party acts as coordinator)
uint32_t cfmp_net_listen(
    FFINetListener **out,
    const char *url,                    // "quic://0.0.0.0:443"
    const Option *opts);

uint32_t cfmp_net_accept(
    FFINetListener *l,
    FFINetEndpoint **ep_out);
```

## Transport registry

Just like crypto interfaces, transports are registered via the link-time registry pattern:

```rust
pub trait TransportKind: Sync {
    fn schemes(&self) -> &[&str];           // ["tcp", "tcp4", "tcp6"]
    fn open(&self, url: &Url, opts: &Options) -> Result<Box<dyn Transport>>;
    fn listen(&self, url: &Url, opts: &Options) -> Result<Box<dyn Listener>>;
}

register_transport!(TcpTransport);
register_transport!(QuicTransport);
register_transport!(WsTransport);
register_transport!(InProcTransport);
register_transport!(MockTransport);
```

## Built-in transports

| Crate | Scheme | Use case |
|---|---|---|
| `confium-net-inproc` | `inproc://` | Tests, single-process simulation |
| `confium-net-tcp` | `tcp://`, `tcp+tls://` | LAN deployment |
| `confium-net-quic` | `quic://` | Modern WAN deployment (multiplexed, encrypted by default) |
| `confium-net-ws` | `ws://`, `wss://` | Browser-facing / cloud-hosted parties |
| `confium-net-mock` | `mock://` | Deterministic CI vectors, replay attack tests |

## Authentication

TC parties must authenticate each other. A malicious peer can corrupt a session. The Transport API supports:

- **TLS / QUIC native cert validation** — for `tcp+tls://` and `quic://`
- **Pre-shared keys** via `opts` — for `tcp://` with application-layer auth
- **Application-layer signatures** — TC session itself signs each round message; transport is unauthenticated but the protocol is safe

The third option is the most flexible — it works over any transport including `inproc`. The TC session includes a `from_party_id` and signs each message with the sender's long-term key. Receivers verify before processing.

## Reliability

Transports are **reliable, ordered, authenticated byte streams** (like TCP). The TC protocol sits on top and assumes those guarantees. Datagram-style transports (UDP, raw QUIC datagrams) are out of scope — wrap them in a reliability layer inside the transport plugin if needed.

## Performance

For typical TC schemes (rounds of small messages, ~100 bytes to ~10 KB), throughput matters less than latency. Confium optimizes for:
- Low connection setup time (QUIC 0-RTT where possible)
- Multiplexed connections (one QUIC stream per round message)
- Backpressure (don't queue unbounded)

## What's NOT here

- **Wire-level protocol for TC messages** — that's the TC plugin's job. Transport just moves bytes.
- **NAT traversal** — out of scope. Parties are expected to be reachable at their advertised URLs. Use a TURN-like relay if needed; Confium doesn't bundle one.
- **Anonymity / mix-network transport** — Tor-style transport is a separate plugin, not in the core set.

## Status

- Not started.
- Depends on: nothing (independent of crypto interfaces).
- Estimated effort: medium. The trait + registry + in-process + mock transports are a week; production TCP/QUIC are another few weeks.

## Reference

- `TODO.roadmap/04-threshold-cryptography.md` — primary consumer
- `TODO.roadmap/01-architecture-overview.md` — pillar design
