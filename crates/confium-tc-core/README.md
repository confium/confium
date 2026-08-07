# confium-tc-core

Core threshold cryptography session primitives for [Confium](https://confium.org).

This crate provides the minimal interface that threshold scheme plugins
(CMP20, FROST, GG18) compile against:

- **Session** state machine and parameters
- **Share** types and adapters
- **Scheme registry** (link-time registration via `inventory`)
- **Party** and **message** types

## Usage

```toml
[dependencies]
confium-tc-core = "0.3"
```

```rust
use confium_tc_core::{Session, SessionParams, TcScheme};

let params = SessionParams {
    threshold: 2,
    party_count: 3,
    scheme: "CMP20-ECDSA-P256".into(),
};
```

## License

BSD-2-Clause
