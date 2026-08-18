"""confium.signatif — the SIGNATIF verification pipeline from Python."""

import secrets
from datetime import datetime, timedelta, timezone

import pytest

confium = pytest.importorskip("confium")
from confium import signatif  # noqa: E402

now = datetime.now(timezone.utc)


def test_module_exposes_the_pipeline():
    assert callable(signatif.verify_trusted_artifact)


def test_malformed_artifact_raises():
    with pytest.raises(ValueError):
        signatif.verify_trusted_artifact(
            {"not": "an artifact"},
            {"not": "a bundle"},
            {"not": "a graph"},
        )


def test_rejects_missing_required_inputs():
    with pytest.raises(TypeError):
        signatif.verify_trusted_artifact()


def test_default_registry_used_when_omitted():
    # A malformed graph must error on the graph, not the registry.
    with pytest.raises(ValueError, match="graph"):
        signatif.verify_trusted_artifact(
            {"artifact_id": "x"},
            {"bundle_version": "1"},
            {"nodes": "not-a-map"},
        )
