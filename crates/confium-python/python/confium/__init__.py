"""Confium Python bindings.

Public API surface:

    >>> import confium
    >>> confium.version()
    '0.3.0'
    >>> confium.composite.ED25519
    'Ed25519'
    >>> tree = confium.transparency.MerkleTree()

See the README for usage examples and the `tests/` directory for
end-to-end integration tests.
"""
from __future__ import annotations

from .confium import (  # type: ignore[attr-defined]
    __version__,
    composite,
    core_version,
    transparency,
    version,
)

__all__ = [
    "__version__",
    "composite",
    "core_version",
    "transparency",
    "version",
]
