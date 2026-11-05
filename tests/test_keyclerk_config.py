"""The KeyClerk configuration of this deployment: rendered from the registers, committed in sync,
valid for the engine, and refused when the installed engine is not the pinned one."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import keyclerk_config as KC  # noqa: E402


def test_the_configuration_is_valid_for_the_engine():
    from keyclerk import config
    assert config.validate(KC.build()) == []
    assert KC.build()["grant_limits"]["operator_kind"] == "vdhome"


def test_another_engine_version_is_refused(monkeypatch):
    import keyclerk
    monkeypatch.setattr(keyclerk, "__version__", "0.0.0")
    with pytest.raises(RuntimeError, match="pins"):
        KC.setup()
