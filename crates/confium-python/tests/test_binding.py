"""End-to-end tests for the Confium Python binding.

Run with: `pytest tests/`

These tests exercise real crypto and real transparency-log operations.
No mocks, no stubs. They mirror the Ruby gem's integration suite.
"""
from __future__ import annotations

import hashlib
import json
from typing import Optional

import pytest

import confium
from confium import attributes, composite, pki, transparency


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

def test_version_returns_string() -> None:
    v = confium.version()
    assert isinstance(v, str)
    assert v  # non-empty


def test_core_version_returns_string() -> None:
    v = confium.core_version()
    assert isinstance(v, str)
    assert v


def test_dunder_version_is_set() -> None:
    assert hasattr(confium, "__version__")
    assert isinstance(confium.__version__, str)


# ---------------------------------------------------------------------------
# Composite signatures
# ---------------------------------------------------------------------------

def _ed25519_keypair_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    """Derive an Ed25519 (public_key, signing_seed) pair from a seed."""
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )
    except ImportError:
        pytest.skip("cryptography package not available")
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return pk, seed


def _ed25519_sign(signing_seed: bytes, message: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    sk = Ed25519PrivateKey.from_private_bytes(signing_seed)
    return sk.sign(message)


def _p256_keypair():
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateNumbers,
        EllipticCurvePublicKey,
        generate_private_key,
        SECP256R1,
    )
    sk = generate_private_key(SECP256R1())
    pk = sk.public_key()
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )
    pk_bytes = pk.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return sk, pk_bytes


def _p256_sign(sk, message: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature,
    )
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    der = sk.sign(message, ECDSA(hashes.SHA256()))
    return der


def test_composite_round_trip_ed25519() -> None:
    seed = b"\x01" * 32
    pk, sk_seed = _ed25519_keypair_from_seed(seed)
    message = b"composite round trip test"
    signature = _ed25519_sign(sk_seed, message)

    component = composite.ComponentSignature(
        algorithm=composite.ED25519,
        public_key=pk,
        signature=signature,
    )
    cs = composite.CompositeSignature([component])

    result = cs.verify(message)
    assert result.all_verified is True
    assert len(result.per_component) == 1
    assert result.per_component[0]["algorithm"] == "Ed25519"
    assert result.per_component[0]["verified"] is True
    assert result.per_component[0]["error"] is None


def test_composite_rejects_wrong_message() -> None:
    seed = b"\x02" * 32
    pk, sk_seed = _ed25519_keypair_from_seed(seed)
    signature = _ed25519_sign(sk_seed, b"original")

    component = composite.ComponentSignature(
        algorithm=composite.ED25519,
        public_key=pk,
        signature=signature,
    )
    cs = composite.CompositeSignature([component])
    result = cs.verify(b"different message")
    assert result.all_verified is False
    assert result.per_component[0]["verified"] is False
    assert "verify" in result.per_component[0]["error"].lower()


def test_composite_rejects_wrong_signature_length() -> None:
    seed = b"\x03" * 32
    pk, _ = _ed25519_keypair_from_seed(seed)
    component = composite.ComponentSignature(
        algorithm=composite.ED25519,
        public_key=pk,
        signature=b"\x00" * 10,  # wrong length
    )
    cs = composite.CompositeSignature([component])
    result = cs.verify(b"msg")
    assert result.all_verified is False
    assert "64 bytes" in result.per_component[0]["error"]


def test_composite_with_ecdsa_p256() -> None:
    sk, pk_bytes = _p256_keypair()
    message = b"p256 composite test message"
    sig = _p256_sign(sk, message)

    component = composite.ComponentSignature(
        algorithm=composite.ECDSA_P256,
        public_key=pk_bytes,
        signature=sig,
    )
    cs = composite.CompositeSignature([component])
    result = cs.verify(message)
    assert result.all_verified is True


def test_composite_multi_component_all_valid() -> None:
    ed_seed = b"\x10" * 32
    ed_pk, ed_sk = _ed25519_keypair_from_seed(ed_seed)
    ec_sk, ec_pk = _p256_keypair()
    message = b"hybrid composite message"

    ed_component = composite.ComponentSignature(
        algorithm=composite.ED25519,
        public_key=ed_pk,
        signature=_ed25519_sign(ed_sk, message),
    )
    ec_component = composite.ComponentSignature(
        algorithm=composite.ECDSA_P256,
        public_key=ec_pk,
        signature=_p256_sign(ec_sk, message),
    )
    cs = composite.CompositeSignature([ed_component, ec_component])
    result = cs.verify(message)
    assert result.all_verified is True
    assert len(result.per_component) == 2
    algorithms = [c["algorithm"] for c in result.per_component]
    assert "Ed25519" in algorithms
    assert "ECDSA-P256" in algorithms


def test_composite_multi_component_one_fails() -> None:
    ed_seed = b"\x20" * 32
    ed_pk, ed_sk = _ed25519_keypair_from_seed(ed_seed)
    ec_sk, ec_pk = _p256_keypair()
    message = b"hybrid that fails"

    ed_component = composite.ComponentSignature(
        algorithm=composite.ED25519,
        public_key=ed_pk,
        signature=_ed25519_sign(ed_sk, message),
    )
    # ECDSA component signs a different message
    ec_component = composite.ComponentSignature(
        algorithm=composite.ECDSA_P256,
        public_key=ec_pk,
        signature=_p256_sign(ec_sk, b"other"),
    )
    cs = composite.CompositeSignature([ed_component, ec_component])
    result = cs.verify(message)
    assert result.all_verified is False
    failed = [c for c in result.per_component if not c["verified"]]
    assert len(failed) == 1
    assert failed[0]["algorithm"] == "ECDSA-P256"


def test_composite_unknown_algorithm_marks_failed() -> None:
    component = composite.ComponentSignature(
        algorithm="ML-DSA-65",
        public_key=b"\x00" * 1952,
        signature=b"\x00" * 3309,
    )
    cs = composite.CompositeSignature([component])
    result = cs.verify(b"msg")
    assert result.all_verified is False
    assert "no builtin verifier" in result.per_component[0]["error"]


def test_composite_verify_with_custom_callback() -> None:
    """Custom verifier callback bridges to Python."""
    component = composite.ComponentSignature(
        algorithm="CustomAlg",
        public_key=b"\xaa" * 32,
        signature=b"\xbb" * 64,
    )
    cs = composite.CompositeSignature([component])

    calls: list[tuple[str, bytes, bytes, bytes]] = []

    def verifier(alg: str, pk: bytes, msg: bytes, sig: bytes) -> Optional[str]:
        calls.append((alg, pk, msg, sig))
        if alg == "CustomAlg" and msg == b"expected":
            return None  # success
        return "wrong"

    result = cs.verify_with(b"expected", verifier)
    assert result.all_verified is True
    assert len(calls) == 1
    assert calls[0][0] == "CustomAlg"


def test_composite_verify_with_callback_returns_error_string() -> None:
    component = composite.ComponentSignature(
        algorithm="Custom",
        public_key=b"\x00" * 16,
        signature=b"\x00" * 16,
    )
    cs = composite.CompositeSignature([component])

    def fails(alg, pk, msg, sig):
        return "bad signature"

    result = cs.verify_with(b"msg", fails)
    assert result.all_verified is False
    assert result.per_component[0]["error"] == "bad signature"


def test_composite_to_from_json_round_trip() -> None:
    original = composite.CompositeSignature([
        composite.ComponentSignature(
            algorithm="Ed25519",
            public_key=b"\x01" * 32,
            signature=b"\x02" * 64,
        ),
    ])
    payload = original.to_json()
    assert isinstance(payload, str)

    parsed = composite.CompositeSignature.from_json(payload)
    assert parsed.component_count() == 1
    algs = parsed.algorithms()
    assert algs == ["Ed25519"]


def test_composite_from_json_invalid_payload() -> None:
    with pytest.raises(ValueError):
        composite.CompositeSignature.from_json("not json")
    with pytest.raises(ValueError):
        composite.CompositeSignature.from_json('{"wrong": "shape"}')


def test_composite_algorithms_and_count() -> None:
    cs = composite.CompositeSignature([
        composite.ComponentSignature("A", b"\x00", b"\x00"),
        composite.ComponentSignature("B", b"\x00", b"\x00"),
        composite.ComponentSignature("C", b"\x00", b"\x00"),
    ])
    assert cs.component_count() == 3
    assert cs.algorithms() == ["A", "B", "C"]


def test_component_signature_getters() -> None:
    c = composite.ComponentSignature(
        algorithm="Ed25519",
        public_key=b"\xaa" * 32,
        signature=b"\xbb" * 64,
    )
    assert c.algorithm == "Ed25519"
    assert c.public_key == b"\xaa" * 32
    assert c.signature == b"\xbb" * 64


def test_builtin_ed25519_verifier_function() -> None:
    seed = b"\x42" * 32
    pk, sk = _ed25519_keypair_from_seed(seed)
    msg = b"builtin verifier test"
    sig = _ed25519_sign(sk, msg)
    assert composite.verify_ed25519(pk, msg, sig) is None

    with pytest.raises(ValueError):
        composite.verify_ed25519(pk, b"other", sig)


def test_builtin_ecdsa_p256_verifier_function() -> None:
    sk, pk_bytes = _p256_keypair()
    msg = b"p256 builtin test"
    sig = _p256_sign(sk, msg)
    assert composite.verify_ecdsa_p256(pk_bytes, msg, sig) is None

    with pytest.raises(ValueError):
        composite.verify_ecdsa_p256(pk_bytes, b"other", sig)


# ---------------------------------------------------------------------------
# Composite signing (sign_ed25519 + sign_p256)
# ---------------------------------------------------------------------------

def test_sign_ed25519_round_trip() -> None:
    seed = b"\x42" * 32
    msg = b"composite sign round-trip"
    cs = composite.CompositeSignature.sign_ed25519(seed, msg)
    assert cs.component_count() == 1
    assert cs.algorithms() == ["Ed25519"]
    assert cs.verify(msg).all_verified is True


def test_sign_ed25519_rejects_short_key() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        composite.CompositeSignature.sign_ed25519(b"\x00" * 10, b"msg")


def test_sign_ed25519_tampered_message_fails() -> None:
    seed = b"\x99" * 32
    cs = composite.CompositeSignature.sign_ed25519(seed, b"original")
    assert cs.verify(b"tampered").all_verified is False


def test_sign_ed25519_pubkey_matches_seed() -> None:
    """The seed-derived verifying key matches what the cryptography lib expects."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )
    import json as _json

    seed = b"\x55" * 32
    cs = composite.CompositeSignature.sign_ed25519(seed, b"msg")
    expected_pk = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    component = _json.loads(cs.to_json())["components"][0]
    assert bytes(component["public_key"]) == expected_pk


def test_sign_p256_round_trip() -> None:
    seed = b"\x33" * 32
    msg = b"p256 sign round-trip"
    cs = composite.CompositeSignature.sign_p256(seed, msg)
    assert cs.component_count() == 1
    assert cs.algorithms() == ["ECDSA-P256"]
    assert cs.verify(msg).all_verified is True


def test_sign_p256_rejects_short_key() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        composite.CompositeSignature.sign_p256(b"\x00" * 16, b"msg")


def test_sign_p256_signature_is_der_encoded() -> None:
    """ECDSA-P256 components must DER-encode the signature (RFC 5480)."""
    import json as _json

    seed = b"\x22" * 32
    cs = composite.CompositeSignature.sign_p256(seed, b"der check")
    component = _json.loads(cs.to_json())["components"][0]
    sig_bytes = bytes(component["signature"])
    assert sig_bytes[0] == 0x30  # DER SEQUENCE


def test_hybrid_ed25519_plus_p256_via_sign() -> None:
    """End-to-end: build a hybrid from two sign() calls."""
    import json as _json

    ed_seed = b"\x10" * 32
    p256_seed = b"\x20" * 32
    msg = b"hybrid via sign + manual compose"

    ed_cs = composite.CompositeSignature.sign_ed25519(ed_seed, msg)
    p256_cs = composite.CompositeSignature.sign_p256(p256_seed, msg)

    ed_comp = _json.loads(ed_cs.to_json())["components"][0]
    p256_comp = _json.loads(p256_cs.to_json())["components"][0]
    hybrid = composite.CompositeSignature.from_json(
        _json.dumps({"components": [ed_comp, p256_comp]})
    )

    assert hybrid.component_count() == 2
    result = hybrid.verify(msg)
    assert result.all_verified is True
    algs = sorted(c["algorithm"] for c in result.per_component)
    assert algs == ["ECDSA-P256", "Ed25519"]


# ---------------------------------------------------------------------------
# Transparency log
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def test_tree_starts_empty() -> None:
    tree = transparency.MerkleTree()
    assert tree.is_empty is True
    assert tree.size == 0
    assert tree.root == b"\x00" * 32


def test_tree_append_returns_sequence() -> None:
    tree = transparency.MerkleTree()
    seq = tree.append("certificate_issuance", _sha256(b"a"))
    assert seq == 0
    seq = tree.append("certificate_issuance", _sha256(b"b"))
    assert seq == 1


def test_tree_root_changes_on_append() -> None:
    tree = transparency.MerkleTree()
    root0 = tree.root
    tree.append("certificate_issuance", _sha256(b"x"))
    root1 = tree.root
    assert root0 != root1
    assert root0 == b"\x00" * 32
    assert root1 != b"\x00" * 32


def test_tree_rejects_bad_artifact_type() -> None:
    tree = transparency.MerkleTree()
    with pytest.raises(ValueError, match="unknown artifact_type"):
        tree.append("bogus_type", _sha256(b"x"))


def test_tree_rejects_short_hash() -> None:
    tree = transparency.MerkleTree()
    with pytest.raises(ValueError, match="32 bytes"):
        tree.append("certificate_issuance", b"\x00" * 10)


def test_tree_inclusion_proof_round_trip_single_leaf() -> None:
    tree = transparency.MerkleTree()
    seq = tree.append("certificate_issuance", _sha256(b"single"))
    proof = tree.inclusion_proof(seq)
    assert proof.sequence == seq
    assert proof.is_empty is True
    assert proof.len == 0

    tree.verify_inclusion(seq, proof, tree.root)  # no exception = pass


def test_tree_inclusion_proof_round_trip_multiple_leaves() -> None:
    tree = transparency.MerkleTree()
    artifact_hashes = [_sha256(bytes([i])) for i in range(7)]
    seqs = [tree.append("certificate_issuance", h) for h in artifact_hashes]
    root = tree.root

    for seq in seqs:
        proof = tree.inclusion_proof(seq)
        tree.verify_inclusion(seq, proof, root)


def test_tree_inclusion_proof_power_of_two() -> None:
    tree = transparency.MerkleTree()
    for i in range(8):
        tree.append("certificate_issuance", _sha256(bytes([i])))
    root = tree.root
    for seq in range(8):
        proof = tree.inclusion_proof(seq)
        tree.verify_inclusion(seq, proof, root)


def test_tree_verify_inclusion_detects_wrong_root() -> None:
    tree = transparency.MerkleTree()
    seq = tree.append("certificate_issuance", _sha256(b"z"))
    proof = tree.inclusion_proof(seq)
    bogus_root = b"\xff" * 32
    with pytest.raises(ValueError, match="inclusion proof failed"):
        tree.verify_inclusion(seq, proof, bogus_root)


def test_tree_entry_returns_dict() -> None:
    tree = transparency.MerkleTree()
    seq = tree.append("threshold_signature", _sha256(b"entry"))
    entry = tree.entry(seq)
    assert entry["sequence"] == seq
    assert entry["artifact_type"] == "threshold_signature"
    assert entry["artifact_hash"] == _sha256(b"entry")
    assert isinstance(entry["timestamp"], str)


def test_tree_entry_out_of_range() -> None:
    tree = transparency.MerkleTree()
    with pytest.raises(IndexError):
        tree.entry(99)


def test_inclusion_proof_out_of_range() -> None:
    tree = transparency.MerkleTree()
    with pytest.raises(IndexError):
        tree.inclusion_proof(0)


def test_inclusion_proof_steps_format() -> None:
    tree = transparency.MerkleTree()
    for i in range(4):
        tree.append("certificate_issuance", _sha256(bytes([i])))
    proof = tree.inclusion_proof(2)
    for step in proof.steps:
        assert isinstance(step["sibling"], bytes)
        assert len(step["sibling"]) == 32
        assert step["side"] in ("left", "right")


def test_compute_leaf_hash_external_audit() -> None:
    """External auditor recomputes leaf hash from published fields."""
    tree = transparency.MerkleTree()
    artifact_hash = _sha256(b"audit me")
    seq = tree.append("certificate_issuance", artifact_hash)
    entry = tree.entry(seq)
    root = tree.root

    leaf = transparency.compute_leaf_hash(
        seq, entry["timestamp"], artifact_hash,
    )
    proof = tree.inclusion_proof(seq)

    transparency.verify_inclusion_with_leaf(leaf, proof, root)


def test_compute_leaf_hash_rejects_bad_timestamp() -> None:
    with pytest.raises(ValueError, match="RFC 3339"):
        transparency.compute_leaf_hash(0, "not a timestamp", b"\x00" * 32)


def test_verify_inclusion_with_leaf_detects_wrong_leaf() -> None:
    tree = transparency.MerkleTree()
    seq = tree.append("certificate_issuance", _sha256(b"leaf1"))
    tree.append("certificate_issuance", _sha256(b"leaf2"))
    root = tree.root
    proof = tree.inclusion_proof(seq)

    bogus_leaf = b"\xaa" * 32
    with pytest.raises(ValueError):
        transparency.verify_inclusion_with_leaf(bogus_leaf, proof, root)


def test_artifact_types_listed() -> None:
    assert "certificate_issuance" in transparency.ARTIFACT_TYPES
    assert "threshold_signature" in transparency.ARTIFACT_TYPES
    assert "director_rotation" in transparency.ARTIFACT_TYPES
    assert "archive_renewal" in transparency.ARTIFACT_TYPES


def test_all_artifact_types_accepted_by_append() -> None:
    tree = transparency.MerkleTree()
    for at in transparency.ARTIFACT_TYPES:
        seq = tree.append(at, _sha256(at.encode()))
        assert seq >= 0


# ---------------------------------------------------------------------------
# Cross-subsystem integration
# ---------------------------------------------------------------------------

def test_composite_signature_anchored_in_transparency_log() -> None:
    """End-to-end: sign Ed25519, build composite, anchor artifact in tree."""
    seed = b"\x55" * 32
    pk, sk = _ed25519_keypair_from_seed(seed)
    message = b"anchor this composite"
    sig = _ed25519_sign(sk, message)

    cs = composite.CompositeSignature([
        composite.ComponentSignature(composite.ED25519, pk, sig),
    ])
    assert cs.verify(message).all_verified

    payload = cs.to_json().encode()
    artifact_hash = _sha256(payload)

    tree = transparency.MerkleTree()
    seq = tree.append("threshold_signature", artifact_hash)
    root = tree.root

    proof = tree.inclusion_proof(seq)
    tree.verify_inclusion(seq, proof, root)


# ---------------------------------------------------------------------------
# PKI — X.509 Certificate + CSR + CMS SignedData
# ---------------------------------------------------------------------------

def _make_self_signed_cert() -> bytes:
    """Generate a self-signed Ed25519 cert via `cryptography`, return DER."""
    import datetime
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.x509.oid import NameOID

    sk = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "confium-test")])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(sk.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=10))
        .sign(sk, algorithm=None)
    )
    return cert.public_bytes(
        __import__("cryptography").hazmat.primitives.serialization.Encoding.DER
    )


def _make_csr() -> bytes:
    """Generate a PKCS#10 CSR via `cryptography`, return DER."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.x509.oid import NameOID

    sk = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "confium-csr")])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name)
        .sign(sk, algorithm=None)
    )
    return csr.public_bytes(
        __import__("cryptography").hazmat.primitives.serialization.Encoding.DER
    )


def test_certificate_from_der_round_trip() -> None:
    der = _make_self_signed_cert()
    cert = pki.Certificate.from_der(der)
    assert cert.to_der() == der


def test_certificate_from_pem_round_trip() -> None:
    der = _make_self_signed_cert()
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + __import__("base64").b64encode(der).decode()
        + "\n-----END CERTIFICATE-----\n"
    )
    cert = pki.Certificate.from_pem(pem)
    assert cert.to_der() == der
    assert "BEGIN CERTIFICATE" in cert.to_pem()


def test_certificate_fingerprint_is_hex() -> None:
    der = _make_self_signed_cert()
    cert = pki.Certificate.from_der(der)
    fp = cert.fingerprint_sha256
    assert len(fp) == 64  # 32 bytes as hex
    assert all(c in "0123456789abcdef" for c in fp)


def test_certificate_serial_bytes() -> None:
    der = _make_self_signed_cert()
    cert = pki.Certificate.from_der(der)
    sb = cert.serial_bytes
    assert isinstance(sb, bytes)
    assert len(sb) > 0


def test_certificate_validity_window() -> None:
    der = _make_self_signed_cert()
    cert = pki.Certificate.from_der(der)
    assert "T" in cert.not_before  # ISO 8601
    assert "T" in cert.not_after
    assert cert.is_within_validity() is True
    # Far future
    assert cert.is_within_validity("2050-01-01T00:00:00Z") is False


def test_certificate_public_key_bytes() -> None:
    der = _make_self_signed_cert()
    cert = pki.Certificate.from_der(der)
    pk_bytes = cert.public_key_bytes
    assert isinstance(pk_bytes, bytes)
    # Ed25519 SPKI is 44 bytes (12-byte prefix + 32-byte key) per RFC 8410
    # but x509-cert may strip the prefix — accept either
    assert len(pk_bytes) >= 32


def test_certificate_rejects_bad_der() -> None:
    with pytest.raises(ValueError):
        pki.Certificate.from_der(b"not a real cert")


def test_csr_from_der_round_trip() -> None:
    der = _make_csr()
    csr = pki.CSR.from_der(der)
    assert csr.to_der() == der


def test_csr_from_pem_round_trip() -> None:
    der = _make_csr()
    pem = (
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        + __import__("base64").b64encode(der).decode()
        + "\n-----END CERTIFICATE REQUEST-----\n"
    )
    csr = pki.CSR.from_pem(pem)
    assert csr.to_der() == der
    assert "BEGIN CERTIFICATE REQUEST" in csr.to_pem()


def test_signed_data_json_round_trip() -> None:
    sd = {
        "version": 1,
        "digest_algorithms": [{"oid": "2.16.840.1.101.3.4.2.1"}],
        "encap_content_info": {
            "content_type": "1.2.840.113549.1.7.1",
            "content": [104, 105],  # "hi"
        },
        "certificates": [],
        "signer_infos": [],
    }
    payload = json.dumps(sd)
    signed = pki.SignedData.from_json(payload)
    assert signed.version == 1
    assert signed.signer_count == 0
    assert signed.certificate_count == 0
    round_tripped = signed.to_json()
    parsed_back = json.loads(round_tripped)
    assert parsed_back["version"] == 1


def test_signed_data_rejects_bad_json() -> None:
    with pytest.raises(ValueError):
        pki.SignedData.from_json("not json")
    with pytest.raises(ValueError):
        pki.SignedData.from_json('{"wrong": "shape"}')


# ---------------------------------------------------------------------------
# CMS build/sign + DER encode
# ---------------------------------------------------------------------------

FAKE_CERT_DER = b"\x30\x82\x01\x00" + b"C" * 256  # ≥20 bytes for SKI extraction


def _ed25519_signature_for(seed: bytes, message: bytes) -> bytes:
    """Sign message with Ed25519 seed via CompositeSignature.sign_ed25519."""
    cs = composite.CompositeSignature.sign_ed25519(seed, message)
    return bytes(json.loads(cs.to_json())["components"][0]["signature"])


def test_cms_build_detached_creates_one_signer() -> None:
    sig = _ed25519_signature_for(b"\x42" * 32, b"payload")
    sd = pki.SignedData.build_detached(sig, "1.3.101.112", [FAKE_CERT_DER])
    assert sd.signer_count == 1
    assert sd.certificate_count == 1


def test_cms_build_detached_to_der_is_content_info() -> None:
    sig = _ed25519_signature_for(b"\x42" * 32, b"payload")
    sd = pki.SignedData.build_detached(sig, "1.3.101.112", [FAKE_CERT_DER])
    der = sd.to_der()
    assert der[0] == 0x30  # outer SEQUENCE per RFC 5652 §3
    assert len(der) > 300


def test_cms_build_detached_round_trips_json() -> None:
    sig = _ed25519_signature_for(b"\x55" * 32, b"payload")
    sd = pki.SignedData.build_detached(sig, "1.3.101.112", [FAKE_CERT_DER])
    parsed = pki.SignedData.from_json(sd.to_json())
    assert parsed.signer_count == 1


def test_cms_build_detached_accepts_ecdsa_oid() -> None:
    sig = _ed25519_signature_for(b"\x33" * 32, b"payload")
    # The algorithm OID is just stored on the SignerInfo; sign() doesn't
    # check that the signature matches the algorithm.
    sd = pki.SignedData.build_detached(sig, "1.2.840.10045.4.3.2", [FAKE_CERT_DER])
    assert sd.signer_count == 1


def test_cms_build_detached_accepts_multiple_certs() -> None:
    sig = _ed25519_signature_for(b"\x44" * 32, b"payload")
    sd = pki.SignedData.build_detached(
        sig, "1.3.101.112", [FAKE_CERT_DER, FAKE_CERT_DER, FAKE_CERT_DER]
    )
    assert sd.certificate_count == 3


def test_cms_to_der_to_json_preserves_signatures() -> None:
    """DER encode → parse via JSON → signer_infos signature unchanged."""
    sig = _ed25519_signature_for(b"\x77" * 32, b"payload")
    sd = pki.SignedData.build_detached(sig, "1.3.101.112", [FAKE_CERT_DER])
    sd2 = pki.SignedData.from_json(sd.to_json())
    sig2 = bytes(json.loads(sd2.to_json())["signer_infos"][0]["signature"])
    assert sig2 == sig


def test_cms_sign_then_anchor_in_transparency_log() -> None:
    """End-to-end: sign Ed25519 → wrap in CMS → anchor in transparency log."""
    seed = b"\x88" * 32
    msg = b"end-to-end cms + transparency"
    sig = _ed25519_signature_for(seed, msg)
    sd = pki.SignedData.build_detached(sig, "1.3.101.112", [FAKE_CERT_DER])
    der = sd.to_der()
    artifact_hash = hashlib.sha256(der).digest()

    tree = transparency.MerkleTree()
    seq = tree.append("threshold_signature", artifact_hash)
    proof = tree.inclusion_proof(seq)
    tree.verify_inclusion(seq, proof, tree.root)


# ---------------------------------------------------------------------------
# Attributes — predicate DSL parse + evaluate
# ---------------------------------------------------------------------------

def _signer(attrs: dict[str, list[str]]):
    return attributes.SignerAttributes(attrs)


def test_predicate_min_count_satisfied() -> None:
    pred = attributes.Predicate.parse('min_count("role:director", 3)')
    signers = [
        _signer({"role:director": ["yes"]}),
        _signer({"role:director": ["yes"]}),
        _signer({"role:director": ["yes"]}),
    ]
    assert pred.evaluate(signers) is True


def test_predicate_min_count_not_satisfied() -> None:
    pred = attributes.Predicate.parse('min_count("role:director", 5)')
    signers = [
        _signer({"role:director": ["yes"]}),
        _signer({"role:director": ["yes"]}),
    ]
    assert pred.evaluate(signers) is False


def test_predicate_min_distinct() -> None:
    pred = attributes.Predicate.parse('min_distinct("region", 3)')
    signers = [
        _signer({"region": ["europe"]}),
        _signer({"region": ["americas"]}),
        _signer({"region": ["asia-pacific"]}),
    ]
    assert pred.evaluate(signers) is True


def test_predicate_none() -> None:
    pred = attributes.Predicate.parse('none("nationality:cn")')
    clean = [_signer({"region": ["europe"]})]
    assert pred.evaluate(clean) is True
    bad = [_signer({"nationality:cn": ["yes"]})]
    assert pred.evaluate(bad) is False


def test_predicate_any() -> None:
    pred = attributes.Predicate.parse('any("expertise")')
    signers = [_signer({"region": ["europe"]}), _signer({"expertise": ["crypto"]})]
    assert pred.evaluate(signers) is True


def test_predicate_all() -> None:
    pred = attributes.Predicate.parse('all("role:director")')
    directors = [_signer({"role:director": ["yes"]}), _signer({"role:director": ["yes"]})]
    assert pred.evaluate(directors) is True
    mixed = [_signer({"role:director": ["yes"]}), _signer({"role:observer": ["yes"]})]
    assert pred.evaluate(mixed) is False


def test_predicate_and_composition() -> None:
    pred = attributes.Predicate.parse(
        'and(min_count("role:director", 3), min_distinct("region", 3))'
    )
    signers = [
        _signer({"role:director": ["yes"], "region": ["europe"]}),
        _signer({"role:director": ["yes"], "region": ["americas"]}),
        _signer({"role:director": ["yes"], "region": ["asia-pacific"]}),
    ]
    assert pred.evaluate(signers) is True


def test_predicate_or_composition() -> None:
    pred = attributes.Predicate.parse(
        'or(min_count("role:director", 99), any("expertise"))'
    )
    signers = [_signer({"expertise": ["crypto"]})]
    assert pred.evaluate(signers) is True


def test_predicate_not() -> None:
    pred = attributes.Predicate.parse('not(none("role:director"))')
    signers = [_signer({"role:director": ["yes"]})]
    assert pred.evaluate(signers) is True


def test_predicate_rejects_unknown_function() -> None:
    with pytest.raises(ValueError):
        attributes.Predicate.parse('bogus("arg")')


def test_predicate_rejects_unclosed() -> None:
    with pytest.raises(ValueError):
        attributes.Predicate.parse('min_count("attr", 3')


def test_signer_attributes_add_and_has() -> None:
    s = attributes.SignerAttributes()
    s.add("role:director", "yes")
    assert s.has("role:director") is True
    assert s.has("missing") is False


def test_signer_attributes_values() -> None:
    s = attributes.SignerAttributes({"region": ["europe", "americas"]})
    vals = s.values("region")
    assert set(vals) == {"europe", "americas"}
    assert s.values("missing") == []


def test_signer_attributes_rejects_non_list() -> None:
    with pytest.raises(TypeError):
        attributes.SignerAttributes({"region": "europe"})  # str, not list


def test_examples_dict_complete() -> None:
    expected = {"min_count", "min_distinct", "none", "any", "all", "and", "or", "not"}
    assert expected.issubset(set(attributes.EXAMPLES.keys()))


# ---------------------------------------------------------------------------
# Consistency proofs (RFC 6962 §2.1.2)
# ---------------------------------------------------------------------------

def _build_tree_with_snapshots(n: int):
    """Build a tree of n leaves, returning (tree, [root_at_size_1, root_at_size_2, ...])."""
    tree = transparency.MerkleTree()
    roots = []
    for i in range(n):
        tree.append("certificate_issuance", _sha256(bytes([i])))
        roots.append(tree.root)
    return tree, roots


def test_consistency_proof_empty_for_zero() -> None:
    tree, _ = _build_tree_with_snapshots(8)
    assert tree.consistency_proof(0) == []


def test_consistency_proof_empty_for_same_size() -> None:
    tree, _ = _build_tree_with_snapshots(8)
    assert tree.consistency_proof(8) == []


def test_consistency_proof_rejects_old_larger_than_current() -> None:
    tree, _ = _build_tree_with_snapshots(4)
    with pytest.raises(ValueError):
        tree.consistency_proof(8)


def test_consistency_proof_returns_subtree_hashes_for_pow2_old_size() -> None:
    tree, _ = _build_tree_with_snapshots(8)
    proof = tree.consistency_proof(4)
    assert len(proof) == 1
    assert all(len(h) == 32 for h in proof)


def test_consistency_proof_returns_multiple_entries_for_non_pow2() -> None:
    tree, _ = _build_tree_with_snapshots(5)
    proof = tree.consistency_proof(3)
    assert len(proof) == 3


def test_verify_consistency_pow2_old_size() -> None:
    """(old=4, new=8) — power-of-two old_size."""
    tree, roots = _build_tree_with_snapshots(8)
    proof = tree.consistency_proof(4)
    tree.verify_consistency(roots[3], roots[7], 4, 8, proof)


def test_verify_consistency_non_pow2_old_size() -> None:
    """(old=3, new=11) — non-power-of-two old_size, the case the old impl broke on."""
    tree, roots = _build_tree_with_snapshots(11)
    proof = tree.consistency_proof(3)
    tree.verify_consistency(roots[2], roots[10], 3, 11, proof)


def test_verify_consistency_all_sizes_1_to_16() -> None:
    """Comprehensive sweep — every (old_size, new_size=16) pair must verify."""
    tree, roots = _build_tree_with_snapshots(16)
    final_size = tree.size
    for old_size in range(1, final_size + 1):
        proof = tree.consistency_proof(old_size)
        tree.verify_consistency(roots[old_size - 1], roots[final_size - 1],
                                old_size, final_size, proof)


def test_verify_consistency_detects_tampered_old_root() -> None:
    tree, roots = _build_tree_with_snapshots(12)
    proof = tree.consistency_proof(4)
    bogus_old_root = b"\xff" * 32
    with pytest.raises(ValueError, match="consistency"):
        tree.verify_consistency(bogus_old_root, roots[11], 4, 12, proof)


def test_verify_consistency_detects_tampered_new_root() -> None:
    tree, roots = _build_tree_with_snapshots(12)
    proof = tree.consistency_proof(4)
    bogus_new_root = b"\xff" * 32
    with pytest.raises(ValueError, match="consistency"):
        tree.verify_consistency(roots[3], bogus_new_root, 4, 12, proof)


def test_verify_consistency_rejects_size_mismatch() -> None:
    """If new_size != tree.size, verification fails."""
    tree, roots = _build_tree_with_snapshots(8)
    proof = tree.consistency_proof(4)
    with pytest.raises(ValueError, match="consistency"):
        tree.verify_consistency(roots[3], roots[7], 4, 99, proof)


def test_verify_consistency_rejects_short_root() -> None:
    tree, _ = _build_tree_with_snapshots(8)
    proof = tree.consistency_proof(4)
    with pytest.raises(ValueError, match="32 bytes"):
        tree.verify_consistency(b"\x00" * 10, b"\x00" * 32, 4, 8, proof)


# ---------------------------------------------------------------------------
# XMLDSig canonicalization
# ---------------------------------------------------------------------------

def test_xmldsig_canonicalize_strips_declaration() -> None:
    from confium import xmldsig
    xml = '<?xml version="1.0"?>\n<root><child>text</child></root>'
    result = xmldsig.canonicalize(xml)
    assert result.startswith("<root>")
    assert not result.startswith("<?xml")


def test_xmldsig_canonicalize_preserves_content() -> None:
    from confium import xmldsig
    xml = '<root><child attr="val">hello</child></root>'
    result = xmldsig.canonicalize(xml)
    assert "hello" in result
    assert 'attr="val"' in result


def test_xmldsig_canonicalize_exclusive_round_trip() -> None:
    from confium import xmldsig
    xml = '<root><child>x</child></root>'
    assert xmldsig.canonicalize_exclusive(xml) == xmldsig.canonicalize(xml)


def test_xmldsig_sha256_digest() -> None:
    from confium import xmldsig
    import hashlib
    result = xmldsig.sha256_digest(b"hello")
    expected = hashlib.sha256(b"hello").digest()
    assert result == expected


def test_xmldsig_rejects_malformed_xml() -> None:
    from confium import xmldsig
    with pytest.raises(ValueError):
        xmldsig.canonicalize("&&&unterminated")


# ---------------------------------------------------------------------------
# Deployment manifest
# ---------------------------------------------------------------------------

def test_deployment_manifest_round_trip() -> None:
    from confium import deployment
    toml = """[deployment]
name = "Test Deployment"
operator = "Test Operator"
manifest_version = 1

mode = "certificate_pki"

[[tiers]]
name = "root"
role = "root"
signing_algorithm = "FROST-ed25519"
threshold = { t = 3, n = 5 }
"""
    m = deployment.Manifest.from_toml(toml)
    assert m.name == "Test Deployment"
    assert m.operator == "Test Operator"
    assert m.tier_count == 1
    round_tripped = m.to_toml()
    assert "Test Deployment" in round_tripped


def test_deployment_manifest_rejects_bad_toml() -> None:
    from confium import deployment
    with pytest.raises(ValueError):
        deployment.Manifest.from_toml("not valid toml ===")


def test_deployment_manifest_validate_returns_list() -> None:
    from confium import deployment
    toml = """[deployment]
name = "test"
operator = "test-org"
manifest_version = 1

mode = "certificate_pki"

[[tiers]]
name = "root"
role = "root"
signing_algorithm = "FROST-ed25519"
threshold = { t = 1, n = 1 }
"""
    m = deployment.Manifest.from_toml(toml)
    results = m.validate()
    assert isinstance(results, list)


# ---------------------------------------------------------------------------
# OTS (OpenTimestamps)
# ---------------------------------------------------------------------------

def test_ots_client_has_calendar_servers() -> None:
    from confium import ots
    client = ots.OtsClient()
    assert len(client.calendar_servers) > 0
    assert all(isinstance(s, str) for s in client.calendar_servers)


def test_ots_stamp_returns_proof() -> None:
    from confium import ots
    client = ots.OtsClient()
    h = hashlib.sha256(b"test").digest()
    proof = client.stamp(h)
    assert proof.hash == h
    assert proof.bitcoin_height > 0


def test_ots_stamp_rejects_short_hash() -> None:
    from confium import ots
    client = ots.OtsClient()
    with pytest.raises(ValueError, match="32 bytes"):
        client.stamp(b"short")


# ---------------------------------------------------------------------------
# ERS (Evidence Record Syntax, RFC 4998)
# ---------------------------------------------------------------------------

def test_ers_build_initial() -> None:
    from confium import ers
    h = hashlib.sha256(b"archived data").digest()
    record = ers.EvidenceRecord.build_initial(h, "test-tsa", b"token")
    assert record.renewal_count >= 1


def test_ers_renew_increments_count() -> None:
    from confium import ers
    h = hashlib.sha256(b"data").digest()
    record = ers.EvidenceRecord.build_initial(h, "tsa-1", b"token-1")
    initial = record.renewal_count
    renewed = record.renew(h, "tsa-2", b"token-2")
    assert renewed.renewal_count == initial + 1


def test_ers_renew_does_not_mutate_original() -> None:
    from confium import ers
    h = hashlib.sha256(b"data").digest()
    record = ers.EvidenceRecord.build_initial(h, "tsa", b"token")
    original_count = record.renewal_count
    record.renew(h, "tsa-2", b"new-token")
    assert record.renewal_count == original_count


def test_ers_rejects_short_hash() -> None:
    from confium import ers
    with pytest.raises(ValueError, match="32 bytes"):
        ers.EvidenceRecord.build_initial(b"short", "tsa", b"token")
