"""Typed exception hierarchy tests for the Python binding.

Run with: `pytest tests/test_errors.py`

Tests the `confium.errors` module that ships in pure-Python source.
The Rust binding raises bare `RuntimeError`; this module's
`translating()` context manager converts matching RuntimeErrors into
typed `ConfiumError` subclasses.
"""

from __future__ import annotations

import pytest

from confium import errors, tc


class TestErrorHierarchy:
    def test_root_inherits_from_exception(self) -> None:
        assert issubclass(errors.ConfiumError, Exception)

    def test_threshold_error_inherits_from_confium_error(self) -> None:
        assert issubclass(errors.ThresholdError, errors.ConfiumError)

    def test_all_subclasses_inherit_from_confium_error(self) -> None:
        for name in (
            "ThresholdError",
            "VerificationError",
            "ValidationError",
            "ParseError",
            "CryptoError",
            "NotFoundError",
            "PolicyViolationError",
            "UnresolvedSignerError",
        ):
            cls = getattr(errors, name)
            assert issubclass(cls, errors.ConfiumError), f"{name} missing"


class TestThresholdError:
    def test_carries_have_and_need_counts(self) -> None:
        e = errors.ThresholdError("insufficient", have_count=2, need_count=3)
        assert e.have_count == 2
        assert e.need_count == 3
        assert e.details["have_count"] == 2
        assert e.details["need_count"] == 3

    def test_message_is_preserved(self) -> None:
        e = errors.ThresholdError("msg", have_count=1, need_count=2)
        assert "msg" in str(e)

    def test_to_dict_shape(self) -> None:
        e = errors.ThresholdError("msg", have_count=1, need_count=2)
        d = e.to_dict()
        assert d["class"] == "ThresholdError"
        assert d["message"] == "msg"
        assert d["details"]["have_count"] == 1


class TestTranslator:
    def test_translator_converts_threshold_runtime_error(self) -> None:
        kg = tc.Cmp20.keygen(threshold=3, party_count=5)
        # Outer pytest.raises catches the translated ThresholdError that
        # the inner `translating()` context manager re-raises.
        with pytest.raises(errors.ThresholdError) as exc_info:
            with errors.translating():
                tc.Cmp20.sign(kg["shares"][:2], threshold=3, message=b"msg")
        assert exc_info.value.need_count == 3
        assert exc_info.value.have_count == 2

    def test_translator_passthrough_for_unmatched_messages(self) -> None:
        with errors.translating():
            with pytest.raises(RuntimeError) as exc_info:
                # Raise something that doesn't match the threshold pattern.
                raise RuntimeError("some other error")
        assert "some other error" in str(exc_info.value)

    def test_translator_is_idempotent(self) -> None:
        # Multiple context managers should compose without conflict.
        with errors.translating():
            with errors.translating():
                pass


class TestOtherErrorShapes:
    def test_verification_error(self) -> None:
        e = errors.VerificationError(
            "bad sig",
            signer_index=2,
            algorithm="Ed25519",
            operation="Composite.verify",
        )
        assert e.signer_index == 2
        assert e.algorithm == "Ed25519"
        assert e.details["operation"] == "Composite.verify"

    def test_validation_error(self) -> None:
        e = errors.ValidationError(
            "bad size",
            param="hash",
            expected="32 bytes",
            actual="10 bytes",
        )
        assert e.param == "hash"
        assert e.expected == "32 bytes"
        assert e.actual == "10 bytes"

    def test_crypto_error(self) -> None:
        e = errors.CryptoError("kdf fail", primitive="hkdf")
        assert e.primitive == "hkdf"

    def test_parse_error(self) -> None:
        e = errors.ParseError("bad PEM", format="pem", offset=5)
        assert e.format == "pem"
        assert e.offset == 5

    def test_not_found_error(self) -> None:
        e = errors.NotFoundError("missing", kind="cert", identifier="abc")
        assert e.kind == "cert"
        assert e.identifier == "abc"

    def test_policy_violation_error(self) -> None:
        e = errors.PolicyViolationError("FIPS", policy="FIPS-140", violation="non-approved")
        assert e.policy == "FIPS-140"
        assert e.violation == "non-approved"

    def test_unresolved_signer_error(self) -> None:
        e = errors.UnresolvedSignerError("no cert", signer_index=3)
        assert e.signer_index == 3
