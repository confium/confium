# `@confium/log-edge` — log.confium.org on pure edge

[![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-orange.svg)](https://workers.cloudflare.com/)
[![D1](https://img.shields.io/badge/Cloudflare-D1-blue.svg)](https://developers.cloudflare.com/d1/)

Pure-edge implementation of `log.confium.org` on Cloudflare
Workers + D1 + Durable Objects + Workers KV. No origin server, no
RDS, no regions to manage. ~$220/month at 100M entries/year scale.

## Why pure edge?

Pure edge works for transparency logs because transparency logs
are **audit systems, not real-time systems**. A cert isn't trusted
the instant it's issued; it's trusted after consumers have had time
to see it in the log (default: 1 hour activation delay). That
window gives eventual consistency time to converge.

See
[`docs/use-cases/public-log-pure-edge.mdx`](../../docs/use-cases/public-log-pure-edge.mdx)
for the full architecture rationale + cost model.

## Architecture

| Component | Role |
|---|---|
| Worker | HTTP entry. Writes to local D1, reads from KV cache. |
| D1 (per-region SQLite) | Accepts writes immediately, replicates globally in seconds. |
| Durable Object `GlobalMerger` | Singleton. Every 5 minutes: pulls pending regional entries, assigns global sequences, recomputes Merkle root, publishes head, invalidates cache. |
| Workers KV | 60-second-TTL read cache for tree head + proofs. |

## Deploy

```sh
# 1. Create the D1 database and KV namespace.
npx wrangler d1 create confium-log
npx wrangler kv namespace create CACHE
# Paste the IDs into wrangler.toml.

# 2. Apply the schema.
npx wrangler d1 execute confium-log --file=./schema.sql
npx wrangler d1 execute confium-log --remote --file=./schema.sql

# 3. Set secrets.
npx wrangler secret put API_TOKEN_SALT

# 4. Deploy.
npx wrangler deploy

# 5. (Optional) Point log.confium.org at the Worker via the
#    Cloudflare dashboard.
```

## API

Identical to the Tier 1/2/3 `confium-log-server`:

- `POST /v1/append` — append a hash
- `POST /v1/certificates` — append a DER cert
- `GET /v1/head` — current tree head
- `GET /v1/proof/<sequence>` — inclusion proof
- `GET /v1/consistency/<old_size>` — consistency proof
- `GET /v1/certificates/<fingerprint>` — cert lookup
- `GET /v1/head/<sequence>/ots` — OTS anchor proof
- `POST /v1/head/<sequence>/witness` — submit witness countersig
- `GET /v1/head/<sequence>/witnesses` — list witnesses
- `GET /v1/health` — health

The only difference: every response includes `activation_time`,
the timestamp after which the entry can be trusted.

## Activation delay policy

Verifiers MUST reject entries whose `activation_time` is in the
future. Default delay: 1 hour (configurable via
`DEFAULT_ACTIVATION_DELAY_SECONDS` in `wrangler.toml`).

This is the same pattern Certificate Transparency uses — Chrome's
CT policy requires hours of monitoring before a cert is trusted.
We're just making it explicit.

## Cost model

See `docs/use-cases/public-log-pure-edge.mdx` for the full table.
TL;DR: ~$220/month at 100M entries/year. 10–50× cheaper than
multi-region PostgreSQL.

## Limitations

- **Activation delay required**. Real-time verification use cases
  should use Tier 2/3 (PostgreSQL primary).
- **D1 write volume** caps around 10M entries/month sustained
  before write pricing starts to bite.
- **Durable Object single-threadedness** is the global sequence
  bottleneck. Throughput: ~10k entries per 5-minute merge cycle.

## License

BSD-2-Clause.

## See also

- [Pure-edge architecture](../../docs/use-cases/public-log-pure-edge.mdx)
- [Tier 1–3 architectures](../../docs/use-cases/public-log-production-architecture.mdx)
- [Cloudflare D1 docs](https://developers.cloudflare.com/d1/)
- [Durable Objects docs](https://developers.cloudflare.com/durable-objects/)
