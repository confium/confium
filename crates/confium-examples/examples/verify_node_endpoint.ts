// Node.js Express endpoint wrapping @confium/confium-wasm.
//
//   npm install express @confium/confium-wasm
//   npx tsx verify_node_endpoint.ts

import express from 'express';
import init, { CompositeSignature } from '@confium/confium-wasm';

const app = express();
app.use(express.json());

let ready = false;
init().then(() => { ready = true; console.log('WASM ready'); });

app.post('/verify/composite', (req, res) => {
  if (!ready) return res.status(503).json({ error: 'still loading' });
  try {
    const { message, signature } = req.body;
    const sig = CompositeSignature.from_json(signature);
    const result = sig.verify(Buffer.from(message, 'base64'));
    res.json({ valid: result.all_verified, components: result.per_component });
  } catch (e) {
    res.status(400).json({ error: (e as Error).message });
  }
});

app.listen(3000, () => console.log('verify-server on :3000'));
