"""The module tree matches the architecture it claims to have.

MASTER_PLAN Part III (D-10), docs/CONTRACTS.md §2 (D-91), D-98.

These assertions look trivial and are not. A module quietly disappearing, or
a fourth layer appearing next to domain/application/adapters, is the kind of
drift that nothing else catches until it has already been built on.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "asip"

# docs/CONTRACTS.md §2 — module to owned PostgreSQL schema (D-91).
MODULE_SCHEMAS = {
    "collection": "sch_collection",
    "evidence": "sch_evidence",
    "extraction": "sch_extraction",
    "baseline": "sch_baseline",
    "detection": "sch_detection",
    "review": "sch_review",
    "identity": "sch_identity",
    "export": "sch_export",
    "reporting": "sch_reporting",
}

LAYERS = ("domain", "application", "adapters")


def test_exactly_the_nine_modules_exist() -> None:
    """No more and no fewer. A tenth module is an architecture change."""
    found = {
        p.name for p in (SRC / "modules").iterdir() if p.is_dir() and not p.name.startswith("_")
    }
    assert found == set(MODULE_SCHEMAS)


@pytest.mark.parametrize("module", sorted(MODULE_SCHEMAS))
def test_module_has_exactly_three_layers(module: str) -> None:
    found = {
        p.name
        for p in (SRC / "modules" / module).iterdir()
        if p.is_dir() and not p.name.startswith("_")
    }
    assert found == set(LAYERS)


@pytest.mark.parametrize("module", sorted(MODULE_SCHEMAS))
def test_module_and_layers_import(module: str) -> None:
    importlib.import_module(f"asip.modules.{module}")
    for layer in LAYERS:
        importlib.import_module(f"asip.modules.{module}.{layer}")


@pytest.mark.parametrize("module,schema", sorted(MODULE_SCHEMAS.items()))
def test_module_declares_the_schema_it_owns(module: str, schema: str) -> None:
    """D-91 is a database fact; the docstring is where a reader meets it."""
    doc = importlib.import_module(f"asip.modules.{module}").__doc__
    assert doc is not None
    assert schema in doc


@pytest.mark.parametrize(
    "package",
    [
        "asip",
        "asip.contracts",
        "asip.contracts.ports",
        "asip.contracts.events",
        "asip.modules",
        "asip.entrypoints",
    ],
)
def test_skeleton_package_imports(package: str) -> None:
    importlib.import_module(package)


def test_composition_root_is_the_only_documented_adapter_importer() -> None:
    """D-98. It raises until Phase 1 wires the first adapters."""
    composition = importlib.import_module("asip.entrypoints.composition")
    with pytest.raises(NotImplementedError, match="Phase 1"):
        composition.build_container()
