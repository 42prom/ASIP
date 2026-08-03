"""D-97 — consumer-driven contract tests.

Each consuming module keeps a fixture of the event shape it depends on under
``tests/contracts/<producer>/``. The producer's own suite validates its output
against every consumer's fixture, so a producer change that would break a
consumer fails in the producer's CI, before merge.

This file is the harness. It is empty of fixtures today because no events
exist yet — the first ones land with the walking skeleton. What it asserts
right now is that the discovery mechanism is wired and that any fixture which
does appear is well-formed and points at a real event schema.

Fixture naming:  tests/contracts/<producer>/<event_name>.v<n>.<consumer>.json
Event schema:    src/asip/contracts/events/<event_name>.v<n>.py   (D-94)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CONTRACT_DIR = REPO / "tests" / "contracts"
EVENTS_DIR = REPO / "src" / "asip" / "contracts" / "events"

MODULES = {
    "collection",
    "evidence",
    "extraction",
    "baseline",
    "detection",
    "review",
    "identity",
    "export",
    "reporting",
}

FIXTURE_NAME = re.compile(
    r"^(?P<event>[a-z0-9_]+)\.v(?P<version>\d+)\.(?P<consumer>[a-z0-9_]+)\.json$"
)

# Every inter-module event carries this envelope (docs/CONTRACTS.md §3).
ENVELOPE = ("schema_version", "event_id", "occurred_at", "trace_id", "tenant_id")


def discover(root: Path) -> list[Path]:
    """Return every consumer fixture under root, sorted for stable test ids."""
    if not root.is_dir():
        return []
    return sorted(p for p in root.glob("*/*.json") if p.is_file())


def _fixture_id(path: Path) -> str:
    return f"{path.parent.name}/{path.name}"


FIXTURES = discover(CONTRACT_DIR)


def test_contract_fixture_root_exists() -> None:
    assert CONTRACT_DIR.is_dir(), "tests/contracts/ is where D-97 fixtures live"


def test_every_producer_directory_is_a_real_module() -> None:
    """A fixture filed under a misspelled producer is never validated."""
    producers = {
        p.name for p in CONTRACT_DIR.iterdir() if p.is_dir() and not p.name.startswith("_")
    }
    unknown = producers - MODULES
    assert not unknown, f"not ASIP modules: {sorted(unknown)}"


@pytest.mark.contracts
@pytest.mark.parametrize("fixture", FIXTURES, ids=_fixture_id)
def test_fixture_is_well_named(fixture: Path) -> None:
    assert FIXTURE_NAME.match(fixture.name), (
        f"expected <event_name>.v<n>.<consumer>.json, got {fixture.name}"
    )


@pytest.mark.contracts
@pytest.mark.parametrize("fixture", FIXTURES, ids=_fixture_id)
def test_fixture_points_at_a_real_event_schema(fixture: Path) -> None:
    """D-94 — every event has a versioned schema module of the same name."""
    match = FIXTURE_NAME.match(fixture.name)
    assert match is not None
    schema = EVENTS_DIR / f"{match['event']}.v{match['version']}.py"
    assert schema.is_file(), f"{fixture.name} pins an event with no schema at {schema}"


@pytest.mark.contracts
@pytest.mark.parametrize("fixture", FIXTURES, ids=_fixture_id)
def test_fixture_carries_the_event_envelope(fixture: Path) -> None:
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    missing = [field for field in ENVELOPE if field not in payload]
    assert not missing, f"{fixture.name} is missing envelope fields: {missing}"


def test_discovery_finds_a_fixture_when_one_exists(tmp_path: Path) -> None:
    """Guards against the suite above passing because discovery is broken.

    With no fixtures committed yet, every parametrised test above collects
    zero cases. That is correct, but it is indistinguishable from a harness
    that silently finds nothing — so prove the harness works.
    """
    (tmp_path / "extraction").mkdir()
    planted = tmp_path / "extraction" / "content_extracted.v1.detection.json"
    planted.write_text("{}", encoding="utf-8")

    assert discover(tmp_path) == [planted]
    assert FIXTURE_NAME.match(planted.name)
