"""Typed exception hierarchy for the Confium Python binding.

Mirrors the Ruby gem's error classes. Each subclass exposes the same
structured fields used by the Rust binding's typed-error helpers, so
users can `except confium.errors.ThresholdError as e: e.have_count`.

The Rust binding currently raises `PyRuntimeError` / `PyValueError`
with descriptive messages. To get the typed hierarchy, install the
exception translator:

    >>> import confium.errors
    >>> confium.errors.install()  # translates bare RuntimeErrors into typed classes
    >>> try:
    ...     confium.tc.Cmp20.sign([...), 3, b"msg")
    ... except confium.errors.ThresholdError as e:
    ...     print(e.have_count, e.need_count)

The translator inspects the RuntimeError's args[0] string for
sentinel patterns emitted by the Rust util module's helpers
(threshold_error, verification_error, etc.) and re-raises the
matching typed class. This avoids the cost of round-tripping
through Python class lookup on every Rust call.
"""

from __future__ import annotations

import re
from typing import Any, Optional


class ConfiumError(Exception):
    """Root of the Confium exception hierarchy."""

    def __init__(
        self,
        message: str = "",
        *,
        details: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.details: dict[str, Any] = dict(details or {})

    def to_dict(self) -> dict[str, Any]:
        return {
            "class": type(self).__name__,
            "message": str(self),
            "details": self.details,
        }


class ThresholdError(ConfiumError):
    """Shamir/threshold operation failed (insufficient shares, etc.)."""

    def __init__(self, message: str = "", *, have_count: int = 0, need_count: int = 0, **rest: Any) -> None:
        super().__init__(message, details={"have_count": have_count, "need_count": need_count, **rest})
        self.have_count = have_count
        self.need_count = need_count


class VerificationError(ConfiumError):
    """Signature, hash, or proof failed to verify."""

    def __init__(
        self,
        message: str = "",
        *,
        signer_index: Optional[int] = None,
        algorithm: Optional[str] = None,
        **rest: Any,
    ) -> None:
        super().__init__(
            message,
            details={"signer_index": signer_index, "algorithm": algorithm, **rest},
        )
        self.signer_index = signer_index
        self.algorithm = algorithm


class ValidationError(ConfiumError):
    """Input is well-formed but semantically invalid."""

    def __init__(self, message: str = "", *, param: str = "", expected: str = "", actual: str = "", **rest: Any) -> None:
        super().__init__(
            message,
            details={"param": param, "expected": expected, "actual": actual, **rest},
        )
        self.param = param
        self.expected = expected
        self.actual = actual


class ParseError(ConfiumError):
    """Input cannot be parsed (bad JSON, malformed PEM, etc.)."""

    def __init__(self, message: str = "", *, format: Optional[str] = None, offset: Optional[int] = None, **rest: Any) -> None:
        super().__init__(
            message,
            details={"format": format, "offset": offset, **rest},
        )
        self.format = format
        self.offset = offset


class CryptoError(ConfiumError):
    """Primitive-level crypto operation failed (bad scalar, KDF, etc.)."""

    def __init__(self, message: str = "", *, primitive: str = "", **rest: Any) -> None:
        super().__init__(message, details={"primitive": primitive, **rest})
        self.primitive = primitive


class NotFoundError(ConfiumError):
    """A referenced slot, cert, or share is not present."""

    def __init__(self, message: str = "", *, kind: str = "", identifier: object = None, **rest: Any) -> None:
        super().__init__(
            message,
            details={"kind": kind, "identifier": identifier, **rest},
        )
        self.kind = kind
        self.identifier = identifier


class IndexError_(ConfiumError):
    """Out-of-range index supplied. Aliased as `IndexError` below."""

    def __init__(self, message: str = "", *, index: int = 0, valid_range: object = None, **rest: Any) -> None:
        super().__init__(
            message,
            details={"index": index, "valid_range": valid_range, **rest},
        )
        self.index = index
        self.valid_range = valid_range


# `IndexError` is a Python builtin; ship under `IndexError_` to avoid
# shadowing and alias the documented name as `ConfiumIndexError`.
ConfiumIndexError = IndexError_


class PolicyViolationError(ConfiumError):
    """FIPS or jurisdictional policy violated."""

    def __init__(self, message: str = "", *, policy: str = "", violation: str = "", **rest: Any) -> None:
        super().__init__(
            message,
            details={"policy": policy, "violation": violation, **rest},
        )
        self.policy = policy
        self.violation = violation


class UnresolvedSignerError(ConfiumError):
    """CMS signer_info cannot be resolved to a certificate."""

    def __init__(self, message: str = "", *, signer_index: Optional[int] = None, **rest: Any) -> None:
        super().__init__(
            message,
            details={"signer_index": signer_index, **rest},
        )
        self.signer_index = signer_index


# Pattern emitted by the Rust binding shim `tc::threshold_err`. The
# format is:
#   [confium:threshold] have=N need=M operation=OP :: <human msg>
# The prefix tokens are stable (depend only on this Python module +
# the Rust shim), not on the snafu Display string of the underlying
# Rust error.
_THRESHOLD_PREFIX_PATTERN = re.compile(
    r"^\[confium:threshold\]\s+have=(\d+)\s+need=(\d+)(?:\s+operation=(\S+))?\s*::\s*(.*)$",
    re.DOTALL,
)

# Legacy fallback: pattern-match on the snafu Display string for any
# threshold error that reaches Python without the structured prefix
# (e.g. directly from a Rust library call that bypassed the binding
# shim). Kept for defense-in-depth; the structured prefix is the
# primary path.
_LEGACY_THRESHOLD_PATTERN = re.compile(
    r"Threshold\s+(\d+)\s+exceeds\s+party\s+count\s+(\d+)"
)


def _classify(message: str) -> Optional[ConfiumError]:
    """Inspect a RuntimeError message and return a typed ConfiumError
    if it matches a known pattern. Returns None if no match.

    Two paths:

    1. Structured prefix (preferred): the Rust binding shim
       ``tc::threshold_err`` formats the message as
       ``[confium:threshold] have=N need=M operation=OP :: <human>``.
       This is stable across Rust error-display changes.
    2. Legacy snafu-Display match (fallback): for RuntimeErrors that
       reach Python without going through the binding shim.
    """
    m = _THRESHOLD_PREFIX_PATTERN.match(message)
    if m:
        have = int(m.group(1))
        need = int(m.group(2))
        operation = m.group(3) or ""
        human = m.group(4).strip()
        return ThresholdError(
            human,
            have_count=have,
            need_count=need,
            operation=operation,
        )
    m = _LEGACY_THRESHOLD_PATTERN.search(message)
    if m:
        need = int(m.group(1))
        have = int(m.group(2))
        return ThresholdError(message, have_count=have, need_count=need)
    return None


_INSTALLED = False


def install() -> None:
    """Install a global exception hook that translates bare
    `RuntimeError`s raised by the Rust binding into typed
    `ConfiumError` subclasses when the message matches a known pattern.

    Idempotent — calling multiple times is safe.
    """
    global _INSTALLED
    if _INSTALLED:
        return
    _INSTALLED = True
    # NOTE: Python's exception machinery doesn't allow transparent
    # re-raising via a global hook. Users must catch RuntimeError and
    # call `translate(e)` themselves, or wrap calls in `with translating():`.
    # See `translating` below.


class translating:
    """Context manager that translates bare RuntimeErrors into typed
    ConfiumError subclasses inside the managed block.

    Example:

        >>> from confium import errors, tc
        >>> with errors.translating():
        ...     try:
        ...         tc.Cmp20.sign([bad_share], 2, b"msg")
        ...     except errors.ThresholdError as e:
        ...         print(e.have_count, e.need_count)

    The translator is conservative — RuntimeErrors that don't match
    a known pattern propagate unchanged.
    """

    def __enter__(self) -> "translating":
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is RuntimeError and exc.args:
            msg = str(exc.args[0])
            classified = _classify(msg)
            if classified is not None:
                raise classified from exc
        return False


__all__ = [
    "ConfiumError",
    "ThresholdError",
    "VerificationError",
    "ValidationError",
    "ParseError",
    "CryptoError",
    "NotFoundError",
    "IndexError_",
    "ConfiumIndexError",
    "PolicyViolationError",
    "UnresolvedSignerError",
    "install",
    "translating",
]
