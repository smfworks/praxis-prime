"""Compliance dials default to off. ARCHITECTURE §17."""

from praxis_prime.policy.dials import (
    BASELINE_SPINE_ALWAYS_ON,
    DIALS,
    PRAXIS_STATE_CODES,
    default_positions,
    dial_ids,
    dials_in_wave,
)


def test_every_dial_defaults_to_off():
    positions = default_positions()
    assert positions
    assert set(positions) == set(dial_ids())
    assert set(positions.values()) == {"off"}
    assert all(dial.id in positions and positions[dial.id] == "off" for dial in DIALS)


def test_dial_ids_are_unique_identifiers():
    ids = dial_ids()
    assert len(ids) == len(set(ids))
    for dial_id in ids:
        assert dial_id.replace("_", "").isalnum()
        assert dial_id == dial_id.lower()


def test_first_wave_and_later_dials():
    first = {dial.id for dial in dials_in_wave("first")}
    later = {dial.id for dial in dials_in_wave("v1.0")}
    assert {"hipaa", "ferpa", "coppa", "gdpr", "state_nc"} <= first
    assert {f"state_{code.lower()}" for code in PRAXIS_STATE_CODES} <= first
    assert later == {"soc2", "eu_ai_act", "ccpa", "pci", "nist_ai_rmf", "iso_42001"}
    assert first.isdisjoint(later)
    assert len(PRAXIS_STATE_CODES) == 13


def test_baseline_spine_is_not_a_dial():
    assert BASELINE_SPINE_ALWAYS_ON is True
    assert "baseline" not in dial_ids()
    assert "spine" not in dial_ids()
