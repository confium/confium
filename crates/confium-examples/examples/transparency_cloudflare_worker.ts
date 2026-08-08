/// <reference types="@cloudflare/workers-types" />
// Confium transparency inclusion proof verifier as a Cloudflare Worker.
//
//   wrangler deploy

import init, { verifyInclusionWithHead } from '@confium/confium-wasm';

export default {
  async fetch(req: Request): Promise<Response> {
    await init();

    const body = await req.json() as { proof: string; head: string };
    const valid = verifyInclusionWithHead(body.proof, body.head);

    return Response.json({ valid });
  },
};
