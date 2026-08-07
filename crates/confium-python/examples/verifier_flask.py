#!/usr/bin/env python3
"""Flask verifier quickstart — three endpoints for the common verifier
workflows:

    POST /verify/composite     composite multi-alg signature
    POST /verify/inclusion     transparency-log inclusion proof
    GET  /health               version + binding status

Run with:

    pip install flask
    python examples/verifier_flask.py
    # in another shell:
    curl http://127.0.0.1:5000/health

Production notes: this example uses Flask's dev server. For real
deployments, swap in gunicorn (``gunicorn -w 4 'examples.verifier_flask:app'``)
and add TLS at the reverse proxy layer.
"""

from __future__ import annotations

import binascii
import json
from typing import Any

from flask import Flask, jsonify, request

import confium
from confium import composite, transparency
from confium.errors import translating

app = Flask(__name__)

MAX_REQUEST_BYTES = 5 * 1024 * 1024  # 5 MiB hard cap


@app.before_request
def reject_too_large() -> Any:
    if request.content_length and request.content_length > MAX_REQUEST_BYTES:
        return jsonify(error="request too large"), 413


@app.get("/health")
def health() -> Any:
    return jsonify(
        ok=True,
        version=confium.version(),
        core_version=confium.core_version(),
    )


@app.post("/verify/composite")
def verify_composite() -> Any:
    body = request.get_json(silent=True) or {}
    sig_json = body.get("composite")
    message_hex = body.get("message")
    if sig_json is None or message_hex is None:
        return jsonify(error="missing 'composite' or 'message'"), 400
    try:
        message = bytes.fromhex(message_hex)
    except (ValueError, binascii.Error) as e:
        return jsonify(error=f"bad message hex: {e}"), 400

    try:
        with translating():
            sig = composite.CompositeSignature.from_json(sig_json)
            result = sig.verify(message)
    except Exception as e:
        return jsonify(error=str(e)), 400

    return jsonify(
        all_verified=result.all_verified,
        per_component=result.per_component,
    )


@app.post("/verify/inclusion")
def verify_inclusion() -> Any:
    body = request.get_json(silent=True) or {}
    required = ("leaf_hash", "proof_steps", "root", "sequence")
    if not all(k in body for k in required):
        return jsonify(error=f"missing required fields: {required}"), 400

    try:
        leaf_hash = bytes.fromhex(body["leaf_hash"])
        root = bytes.fromhex(body["root"])
    except (ValueError, binascii.Error) as e:
        return jsonify(error=f"bad hex: {e}"), 400

    try:
        with translating():
            tree = transparency.MerkleTree()
            ok = tree.verify_inclusion(
                leaf_hash=leaf_hash,
                sequence=body["sequence"],
                steps=[
                    {"sibling": bytes.fromhex(s["sibling"]), "side": s["side"]}
                    for s in body["proof_steps"]
                ],
                root=root,
            )
    except Exception as e:
        return jsonify(error=str(e)), 400

    return jsonify(verified=bool(ok))


@app.errorhandler(404)
def not_found(_e: Any) -> Any:
    return jsonify(error="not found"), 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
