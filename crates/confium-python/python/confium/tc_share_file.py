"""Filesystem-backed share persistence.

Share blobs produced by ``confium.tc.Cmp20.keygen`` /
``confium.tc.Gg18.keygen`` are 71-byte ``bytes`` objects. This module
wraps them in a JSON envelope so they can be saved to disk,
transferred between hosts, and loaded back without encoding
ambiguity.

The envelope format (identical to what the Ruby gem's
``Confium::TC::ShareFile`` produces):

    {
      "scheme":      "CMP20-ECDSA-P256",
      "threshold":   null,
      "party_count": 5,
      "public_key":  "<33-byte hex>",
      "shares":      ["<71-byte hex>", ...]
    }

``threshold`` is included for symmetry with the Ruby side but left
``null`` by ``from_keygen`` — the keygen result doesn't carry it,
callers know it from how they called keygen. ``ShareFile.sign`` does
not consume threshold; callers pass it explicitly to
``tc.Cmp20.sign`` / ``tc.Gg18.sign``.

A file saved from one binding can be loaded by the other.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class ShareFile:
    scheme: str
    party_count: int
    public_key: bytes
    shares: List[bytes]
    threshold: Optional[int] = None

    @classmethod
    def from_keygen(cls, scheme: str, keygen_result: dict) -> "ShareFile":
        """Build a ShareFile from a CMP20 / GG18 keygen result dict.

        ``keygen_result`` is the dict returned by
        ``tc.Cmp20.keygen(...)`` / ``tc.Gg18.keygen(...)`` with
        ``shares`` and ``public_key`` keys.
        """
        return cls(
            scheme=scheme,
            party_count=len(keygen_result["shares"]),
            public_key=keygen_result["public_key"],
            shares=list(keygen_result["shares"]),
            threshold=None,
        )

    @classmethod
    def load(cls, path: str | Path) -> "ShareFile":
        """Load a ShareFile from a JSON file at ``path``."""
        return cls.from_json(Path(path).read_text())

    @classmethod
    def from_json(cls, json_str: str) -> "ShareFile":
        d = json.loads(json_str)
        return cls(
            scheme=d["scheme"],
            party_count=d["party_count"],
            public_key=bytes.fromhex(d["public_key"]),
            shares=[bytes.fromhex(h) for h in d["shares"]],
            threshold=d.get("threshold"),
        )

    def save(self, path: str | Path) -> "ShareFile":
        """Save to ``path`` as JSON. Creates parent directories if missing."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.to_json())
        return self

    def to_json(self) -> str:
        return json.dumps(
            {
                "scheme": self.scheme,
                "threshold": self.threshold,
                "party_count": self.party_count,
                "public_key": self.public_key.hex(),
                "shares": [s.hex() for s in self.shares],
            }
        )

    def to_dict(self) -> dict:
        """Return the envelope as a plain dict (for in-memory callers)."""
        return {
            "scheme": self.scheme,
            "threshold": self.threshold,
            "party_count": self.party_count,
            "public_key": self.public_key,
            "shares": self.shares,
        }
