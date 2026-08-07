// log.confium.org — pure-edge implementation.
//
// Three Cloudflare primitives:
//   1. Worker — handles HTTP, writes to local D1, reads from KV cache.
//   2. D1 — per-region SQLite, eventually consistent globally.
//   3. Durable Object "GlobalMerger" — singleton, runs every 5 min to
//      merge regional logs into the global Merkle tree, publish tree
//      head, submit OTS anchor.
//
// Why pure edge works for a transparency log:
//   - Transparency logs are audit systems, not real-time systems.
//   - Cert isn't trusted until `activation_time` has passed (1 hour default).
//   - The activation window gives the merger time to converge.
//   - Same pattern Certificate Transparency uses (Chrome's CT policy
//     requires hours of monitoring before trusting a cert).
//
// See docs/use-cases/public-log-pure-edge.mdx for the architecture.

import { GlobalMerger } from "./merger.js";

export { GlobalMerger };

// ===== Worker entry point =====

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight.
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    try {
      // ----- Append path: write to regional D1 -----
      if (path === "/v1/append" && request.method === "POST") {
        return await handleAppend(request, env);
      }
      if (path === "/v1/certificates" && request.method === "POST") {
        return await handleAppendCertificate(request, env);
      }

      // ----- Read path: serve from KV cache, fall back to D1 -----
      if (path === "/v1/head") {
        return await handleHead(env);
      }
      if (path.startsWith("/v1/proof/")) {
        const seq = parseInt(path.split("/").pop(), 10);
        return await handleProof(seq, env);
      }
      if (path.startsWith("/v1/consistency/")) {
        const oldSize = parseInt(path.split("/").pop(), 10);
        return await handleConsistency(oldSize, env);
      }
      if (path.startsWith("/v1/certificates/")) {
        const fp = decodeURIComponent(path.split("/").pop());
        return await handleLookupCertificate(fp, env);
      }
      if (path.startsWith("/v1/head/") && path.endsWith("/ots")) {
        const seq = parseInt(path.split("/")[3], 10);
        return await handleOts(seq, env);
      }
      if (path.startsWith("/v1/head/") && path.endsWith("/witness")) {
        const seq = parseInt(path.split("/")[3], 10);
        if (request.method === "POST") {
          return await handlePostWitness(seq, request, env);
        }
      }
      if (path.startsWith("/v1/head/") && path.endsWith("/witnesses")) {
        const seq = parseInt(path.split("/")[3], 10);
        return await handleListWitnesses(seq, env);
      }
      if (path === "/v1/health") {
        return await handleHealth(env);
      }

      return json({ error: "not found" }, 404);
    } catch (err) {
      console.error("request failed", err);
      return json({ error: err.message }, 500);
    }
  },
};

// ===== Append: write to regional D1 =====

async function handleAppend(request, env) {
  const body = await request.json();
  if (!body.artifact_hash || !body.artifact_type) {
    return json({ error: "missing artifact_hash or artifact_type" }, 400);
  }
  if (!/^[0-9a-f]{64}$/.test(body.artifact_hash)) {
    return json({ error: "artifact_hash must be 64 hex chars (SHA-256)" }, 400);
  }

  // Region is auto-detected by Cloudflare (the colo that received the
  // request). In production, this is a real IATA code like "SFO".
  const region = request.cf?.colo || "dev";
  const now = new Date();
  const activationDelayMs = (env.DEFAULT_ACTIVATION_DELAY_SECONDS || 3600) * 1000;
  const activationTime = new Date(now.getTime() + activationDelayMs);

  // Assign a regional sequence. SQLite handles the auto-increment.
  const result = await env.DB.prepare(
    `INSERT INTO regional_entries
       (regional_sequence, region, local_sequence, artifact_type, artifact_hash,
        timestamp, activation_time)
     VALUES (?1, ?2, 0, ?3, ?4, ?5, ?6)
     RETURNING regional_sequence`
  )
    .bind(
      `${region}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      region,
      body.artifact_type,
      body.artifact_hash,
      now.toISOString(),
      activationTime.toISOString()
    )
    .first();

  // Trigger the merger asynchronously (the worker doesn't wait).
  const merger = env.MERGER.idFromName("global");
  ctx.waitUntil(merger.fetch(`https://internal/trigger-merge`));

  return json({
    regional_sequence: result.regional_sequence,
    activation_time: activationTime.toISOString(),
    timestamp: now.toISOString(),
    note: `Entry visible in global tree within ~5 minutes. Trustable after ${activationTime.toISOString()}.`,
  }, 201);
}

async function handleAppendCertificate(request, env) {
  const body = await request.json();
  if (!body.certificate_der) {
    return json({ error: "missing certificate_der (base64)" }, 400);
  }
  // Parse the cert to extract metadata. In production this uses the
  // PKI module; here we just compute the fingerprint.
  const der = base64Decode(body.certificate_der);
  const fingerprint = await sha256Hex(der);

  const region = request.cf?.colo || "dev";
  const now = new Date();
  const activationDelayMs = (env.DEFAULT_ACTIVATION_DELAY_SECONDS || 3600) * 1000;
  const activationTime = new Date(now.getTime() + activationDelayMs);

  const result = await env.DB.prepare(
    `INSERT INTO regional_entries
       (regional_sequence, region, local_sequence, artifact_type, artifact_hash,
        timestamp, activation_time, fingerprint_sha256,
        issuer_dn, subject_dn, valid_from, valid_to)
     VALUES (?1, ?2, 0, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
     RETURNING regional_sequence`
  )
    .bind(
      `${region}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      region,
      classifyCert(body.metadata || {}),
      fingerprint,
      now.toISOString(),
      activationTime.toISOString(),
      fingerprint,
      body.metadata?.issuer_dn || null,
      body.metadata?.subject_dn || null,
      body.metadata?.valid_from || null,
      body.metadata?.valid_to || null
    )
    .first();

  const merger = env.MERGER.idFromName("global");
  ctx.waitUntil(merger.fetch(`https://internal/trigger-merge`));

  return json({
    regional_sequence: result.regional_sequence,
    fingerprint_sha256: fingerprint,
    activation_time: activationTime.toISOString(),
    artifact_type: classifyCert(body.metadata || {}),
    note: `Cert trustable after ${activationTime.toISOString()}.`,
  }, 201);
}

// ===== Read: KV cache + D1 fallback =====

async function handleHead(env) {
  const cached = await env.CACHE.get("head:v1", "json");
  if (cached) return json(cached);

  // Fall back to the latest global tree head in D1.
  const head = await env.DB.prepare(
    `SELECT tree_size, root_hash, timestamp FROM global_tree_heads
     ORDER BY tree_size DESC LIMIT 1`
  ).first();
  if (head) {
    ctx.waitUntil(env.CACHE.put("head:v1", JSON.stringify(head), { expirationTtl: 60 }));
  }
  return json(head || { tree_size: 0, root_hash: "00".repeat(32), timestamp: null });
}

async function handleProof(sequence, env) {
  const cacheKey = `proof:v1:${sequence}`;
  const cached = await env.CACHE.get(cacheKey, "json");
  if (cached) return json(cached);

  // For the scaffold we return the entry's metadata; production
  // computes a real Merkle inclusion proof.
  const entry = await env.DB.prepare(
    `SELECT * FROM regional_entries WHERE global_sequence = ?1`
  ).bind(sequence).first();

  if (!entry) return json({ error: `no entry at global sequence ${sequence}` }, 404);
  const response = { sequence, entry, note: "Full Merkle proof computed by the merger DO." };
  ctx.waitUntil(env.CACHE.put(cacheKey, JSON.stringify(response), { expirationTtl: 300 }));
  return json(response);
}

async function handleConsistency(oldSize, env) {
  // Production computes a real RFC 6962 §2.1.2 proof.
  return json({
    old_size: oldSize,
    new_size: (await handleHead(env).then(r => r.json())).tree_size,
    proof: [],
    note: "Computed by merger DO; scaffold returns empty.",
  });
}

async function handleLookupCertificate(fingerprint, env) {
  const entries = await env.DB.prepare(
    `SELECT * FROM regional_entries WHERE fingerprint_sha256 = ?1
     ORDER BY global_sequence ASC`
  ).bind(fingerprint).all();
  if (entries.results.length === 0) {
    return json({ error: `no entries for fingerprint ${fingerprint}` }, 404);
  }
  return json({ fingerprint, entries: entries.results });
}

async function handleOts(sequence, env) {
  const row = await env.DB.prepare(
    `SELECT ots_proof, bitcoin_height, timestamp FROM global_tree_heads
     WHERE tree_size = ?1`
  ).bind(sequence).first();
  if (!row || !row.ots_proof) {
    return json({ error: `no OTS proof for tree size ${sequence}` }, 404);
  }
  return json({
    tree_size: sequence,
    ots_proof: base64Encode(new Uint8Array(row.ots_proof)),
    bitcoin_height: row.bitcoin_height,
    anchor_time: row.timestamp,
  });
}

async function handlePostWitness(sequence, request, env) {
  const body = await request.json();
  if (!body.witness_id || !body.signature) {
    return json({ error: "missing witness_id or signature" }, 400);
  }
  await env.DB.prepare(
    `INSERT OR REPLACE INTO witness_sigs
       (tree_size, witness_id, signature, timestamp)
     VALUES (?1, ?2, ?3, ?4)`
  ).bind(sequence, body.witness_id, base64Decode(body.signature), new Date().toISOString()).run();
  return json({ accepted: true, witness_id: body.witness_id });
}

async function handleListWitnesses(sequence, env) {
  const rows = await env.DB.prepare(
    `SELECT witness_id, signature, timestamp FROM witness_sigs
     WHERE tree_size = ?1 ORDER BY witness_id`
  ).bind(sequence).all();
  return json({
    tree_size: sequence,
    witnesses: rows.results.map(r => ({
      witness_id: r.witness_id,
      signature: base64Encode(new Uint8Array(r.signature)),
      timestamp: r.timestamp,
    })),
  });
}

async function handleHealth(env) {
  const count = await env.DB.prepare(`SELECT COUNT(*) as n FROM regional_entries`).first();
  return json({
    ok: true,
    region: "auto",
    entry_count: count?.n || 0,
    version: "0.1.0-edge",
  });
}

// ===== Helpers =====

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

function classifyCert(meta) {
  const subj = (meta.subject_dn || "").toLowerCase();
  if (subj.includes("cnml")) return "cnml_certificate";
  if (subj.includes("code sign")) return "code_signing_certificate";
  if (subj.includes("email") || subj.includes("smime")) return "email_signing_certificate";
  if (subj.includes("document")) return "document_signing_certificate";
  if (subj.includes("tsa") || subj.includes("timestamp")) return "timestamping_certificate";
  return "x509_certificate";
}

function base64Decode(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

function base64Encode(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

async function sha256Hex(bytes) {
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}
