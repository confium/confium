// GlobalMerger Durable Object — singleton that produces the global
// Merkle tree head from regional D1 replicas.
//
// Why a Durable Object?
//   - Durable Objects are strongly consistent by definition (single
//     instance globally). The merger needs this for sequence
//     assignment — every region's regional entries must end up with
//     a unique global sequence.
//   - Storage is per-DO, replicated. Survives Worker restarts.
//   - The DO can run on a schedule (alarm) without external triggers.

export class GlobalMerger {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.storage = state.storage;
  }

  async fetch(request) {
    // Trigger a merge cycle (called from the Worker after every
    // append, and also on the alarm schedule below).
    await this.runMerge();
    return new Response("merge triggered");
  }

  async alarm() {
    await this.runMerge();
    // Schedule the next run. Every 5 minutes.
    this.state.storage.setAlarm(Date.now() + 5 * 60 * 1000);
  }

  async runMerge() {
    // 1. Pull all regional entries that haven't been assigned a global sequence.
    const pending = await this.env.DB.prepare(
      `SELECT * FROM regional_entries
       WHERE global_sequence IS NULL
       ORDER BY timestamp ASC`
    ).all();

    if (pending.results.length === 0) {
      // Nothing to merge. Still need to publish a current head.
      return;
    }

    // 2. Get the current max global sequence.
    const maxSeq = await this.env.DB.prepare(
      `SELECT COALESCE(MAX(global_sequence), 0) as max FROM regional_entries`
    ).first();
    let nextSeq = (maxSeq?.max || 0) + 1;

    // 3. Assign global sequences to all pending entries, in stable order.
    //    Stable order = (timestamp, region, regional_sequence). This
    //    makes the global order deterministic across merger runs.
    const sorted = pending.results.sort((a, b) => {
      const tsCmp = a.timestamp.localeCompare(b.timestamp);
      if (tsCmp !== 0) return tsCmp;
      const regionCmp = a.region.localeCompare(b.region);
      if (regionCmp !== 0) return regionCmp;
      return a.regional_sequence.localeCompare(b.regional_sequence);
    });

    for (const entry of sorted) {
      await this.env.DB.prepare(
        `UPDATE regional_entries SET global_sequence = ?1
         WHERE regional_sequence = ?2`
      ).bind(nextSeq, entry.regional_sequence).run();
      nextSeq++;
    }

    // 4. Recompute the global Merkle tree.
    const allHashes = await this.env.DB.prepare(
      `SELECT artifact_hash FROM regional_entries
       WHERE global_sequence IS NOT NULL
       ORDER BY global_sequence ASC`
    ).all();
    const root = await computeMerkleRoot(allHashes.results.map(r => r.artifact_hash));

    // 5. Publish the new tree head.
    const treeSize = nextSeq - 1;
    const timestamp = new Date().toISOString();
    await this.env.DB.prepare(
      `INSERT OR REPLACE INTO global_tree_heads
         (tree_size, root_hash, timestamp)
       VALUES (?1, ?2, ?3)`
    ).bind(treeSize, root, timestamp).run();

    // 6. Invalidate the KV cache for /v1/head.
    await this.env.CACHE.delete("head:v1");

    // 7. Submit OTS anchor (placeholder; real impl uses the OTS calendar protocol).
    // await this.submitOtsAnchor(treeSize, root);

    console.log(`merged ${pending.results.length} entries; tree_size=${treeSize}, root=${root.slice(0, 16)}...`);
  }

  async submitOtsAnchor(treeSize, root) {
    // Production: POST the root to multiple OTS calendar servers,
    // aggregate their responses into a single OTS proof, store it.
    // Skipped in the scaffold — the placeholder proof is enough to
    // make the API surface testable end-to-end.
    const placeholder = new Uint8Array([
      0x4f, 0x54, 0x53, 0x2d, 0x50, 0x4c, 0x41, 0x43, 0x45, 0x48, 0x4f, 0x4c, 0x44, 0x45, 0x52, 0x2f,
      0x76, 0x31,
      ...uint64ToBytes(treeSize),
      ...hexToBytes(root),
    ]);
    await this.env.DB.prepare(
      `UPDATE global_tree_heads SET ots_proof = ?1 WHERE tree_size = ?2`
    ).bind(placeholder.buffer, treeSize).run();
  }
}

async function computeMerkleRoot(hashesHex) {
  // Iterative SHA-256 reduction. Each level combines pairs of
  // sibling hashes. The leaf hash is just the artifact hash; for a
  // real RFC 6962 implementation this would be hash_leaf(entry_hash)
  // to prevent second-preimage attacks.
  if (hashesHex.length === 0) return "00".repeat(32);
  let level = hashesHex.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = hexToBytes(level[i]);
      const right = i + 1 < level.length ? hexToBytes(level[i + 1]) : left;
      const combined = new Uint8Array(left.length + right.length);
      combined.set(left, 0);
      combined.set(right, left.length);
      const hash = await crypto.subtle.digest("SHA-256", combined);
      next.push(bytesToHex(new Uint8Array(hash)));
    }
    level = next;
  }
  return level[0];
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function uint64ToBytes(n) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setBigUint64(0, BigInt(n));
  return new Uint8Array(buf);
}
