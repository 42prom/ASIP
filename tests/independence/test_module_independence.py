"""D-99 — every module is independently removable.

For each of the nine modules in turn: remove it from the package, then import
every other module and every layer of it. All must still import.

A module that cannot be removed without breaking someone else's import is not
a puzzle piece, whatever the directory layout suggests. import-linter checks
the *direction* of imports; this checks whether they exist at all.

Each case runs in a subprocess so that one blocked module cannot leak into the
next through sys.modules.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

MODULES = (
    "collection",
    "evidence",
    "extraction",
    "baseline",
    "detection",
    "review",
    "identity",
    "export",
    "reporting",
)

LAYERS = ("domain", "application", "adapters")

DRIVER = textwrap.dedent(
    """
    import importlib
    import sys

    blocked = {blocked!r}
    targets = {targets!r}


    class Removed:
        \"\"\"Makes `blocked` behave as though it were deleted from the package.\"\"\"

        def find_spec(self, fullname, path=None, target=None):
            if fullname == blocked or fullname.startswith(blocked + "."):
                raise ImportError(
                    f"{{fullname}} was removed for the D-99 independence test"
                )
            return None


    sys.meta_path.insert(0, Removed())

    for name in targets:
        importlib.import_module(name)

    print("OK")
    """
)


def _surviving_targets(removed: str) -> list[str]:
    targets = ["asip", "asip.contracts", "asip.contracts.ports", "asip.contracts.events"]
    for module in MODULES:
        if module == removed:
            continue
        targets.append(f"asip.modules.{module}")
        targets.extend(f"asip.modules.{module}.{layer}" for layer in LAYERS)
    targets.append("asip.entrypoints")
    return targets


@pytest.mark.parametrize("removed", MODULES)
def test_removing_a_module_leaves_the_others_importable(removed: str) -> None:
    code = DRIVER.format(
        blocked=f"asip.modules.{removed}",
        targets=_surviving_targets(removed),
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"Removing asip.modules.{removed} broke another module's import (D-99).\n{result.stderr}"
    )
    assert result.stdout.strip().endswith("OK")


def test_the_removal_mechanism_actually_removes() -> None:
    """Guards against the suite above passing because nothing was blocked.

    Without this, a bug in the meta-path finder would make all nine cases
    pass for the wrong reason — the exact failure mode D-99 exists to avoid.
    """
    code = DRIVER.format(
        blocked="asip.modules.evidence",
        targets=["asip.modules.evidence"],
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "removed for the D-99 independence test" in result.stderr
