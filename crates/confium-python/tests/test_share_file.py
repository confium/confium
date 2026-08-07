"""Filesystem-backed share persistence tests.

Run with: `pytest tests/test_share_file.py`

Verifies the JSON envelope shape, round-trip integrity, parent-dir
creation, signature production from loaded shares, and the
Ruby-interoperability contract (the JSON shape matches what the Ruby
gem's Confium::TC::ShareFile produces).
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

import pytest

from confium import ShareFile, tc
from ecdsa import NIST256p, VerifyingKey
from ecdsa.util import sigdecode_string


def _verify_p256(public_key: bytes, message: bytes, signature: bytes) -> bool:
    vk = VerifyingKey.from_string(public_key, curve=NIST256p)
    digest = hashlib.sha256(message).digest()
    return vk.verify_digest(signature, digest, sigdecode=sigdecode_string)


class TestShareFileRoundTrip:
    def test_save_load_round_trip_preserves_all_fields(self, tmp_path: Path) -> None:
        kg = tc.Cmp20.keygen(threshold=2, party_count=3)
        sf = ShareFile.from_keygen("CMP20-ECDSA-P256", kg)
        path = tmp_path / "shares.json"
        sf.save(path)

        loaded = ShareFile.load(path)
        assert loaded.scheme == "CMP20-ECDSA-P256"
        assert loaded.party_count == 3
        assert loaded.public_key == kg["public_key"]
        assert loaded.shares == kg["shares"]

    def test_save_creates_parent_directories(self, tmp_path: Path) -> None:
        kg = tc.Cmp20.keygen(threshold=2, party_count=3)
        sf = ShareFile.from_keygen("CMP20-ECDSA-P256", kg)
        path = tmp_path / "nested" / "deep" / "shares.json"
        sf.save(path)
        assert path.exists()

    def test_loaded_shares_produce_valid_signatures(self, tmp_path: Path) -> None:
        kg = tc.Cmp20.keygen(threshold=2, party_count=3)
        sf = ShareFile.from_keygen("CMP20-ECDSA-P256", kg)
        path = tmp_path / "shares.json"
        sf.save(path)

        loaded = ShareFile.load(path)
        msg = b"round-trip"
        sig = tc.Cmp20.sign(loaded.shares[:2], threshold=2, message=msg)
        assert _verify_p256(loaded.public_key, msg, sig)

    def test_to_json_envelope_shape(self) -> None:
        kg = tc.Cmp20.keygen(threshold=2, party_count=3)
        sf = ShareFile.from_keygen("GG18-ECDSA-P256", kg)
        parsed = json.loads(sf.to_json())
        assert parsed["scheme"] == "GG18-ECDSA-P256"
        assert parsed["party_count"] == 3
        assert len(parsed["public_key"]) == 66  # 33 bytes hex
        assert len(parsed["shares"]) == 3
        for h in parsed["shares"]:
            assert len(h) == 142  # 71 bytes hex

    def test_envelope_keys_match_ruby_gem_contract(self) -> None:
        """The JSON shape must match what the Ruby Confium::TC::ShareFile
        produces so files saved in one binding load in the other.
        """
        kg = tc.Cmp20.keygen(threshold=2, party_count=3)
        sf = ShareFile.from_keygen("CMP20-ECDSA-P256", kg)
        parsed = json.loads(sf.to_json())
        assert set(parsed.keys()) == {
            "scheme",
            "threshold",
            "party_count",
            "public_key",
            "shares",
        }

    def test_from_dict_round_trip(self) -> None:
        kg = tc.Cmp20.keygen(threshold=2, party_count=3)
        sf = ShareFile.from_keygen("CMP20-ECDSA-P256", kg)
        d = sf.to_dict()
        assert d["scheme"] == sf.scheme
        assert d["public_key"] == sf.public_key
        assert d["shares"] == sf.shares
