"""The gate's own pytest plugin: the change under test cannot turn its own tests green.

Loaded by tools/gate.py with `-p gate_guard`; it writes a JSON record to the path in GATE_GUARD_REPORT:
- the raw outcome of every test, taken from the call itself (`call.excinfo`) in an innermost hook wrapper, before any
  other plugin can rewrite the report that ends up in the JUnit file;
- every plugin registered after the session started (a test module or conftest that registers hooks at import time).
The gate reads this record instead of trusting the JUnit file; a missing record is a red gate.

`scan(paths)` is the static half: test code may not import gc, _pytest or this module, touch a plugin manager, or
define pytest hooks outside the allow-list.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path

import pytest

ALLOWED_CONFTEST_HOOKS = {"pytest_configure"}   # none are defined today; widening this list is a decision
FORBIDDEN_MODULES = {"gc", "_pytest", "gate_guard", "pluggy"}
FORBIDDEN_ATTRS = {"pluginmanager", "_pluginmanager", "hook", "register"}
PURE = {"scan", "changed_asserts", "assert_map"}   # functions without state that tests may import

_raw: dict[str, str] = {}
_plugins_at_start: set[int] = set()
_late: list[str] = []


def pytest_sessionstart(session):
    _plugins_at_start.update(id(p) for p in session.config.pluginmanager.get_plugins())


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_runtest_makereport(item, call):
    # trylast hook wrappers are the innermost: this sees the call before any other wrapper can touch the report
    exc = call.excinfo
    if call.when == "call" or exc is not None:
        if exc is None:
            outcome = "passed"
        elif exc.errisinstance(pytest.skip.Exception):
            outcome = "skipped"
        else:
            outcome = "failed"
        prev = _raw.get(item.nodeid)
        if prev != "failed":   # a failure in setup, call or teardown stays a failure
            _raw[item.nodeid] = outcome if call.when == "call" or outcome != "passed" else (prev or "passed")
    yield


def pytest_collection_finish(session):
    _check_plugins(session.config)


def pytest_sessionfinish(session, exitstatus):
    _check_plugins(session.config)
    path = os.environ.get("GATE_GUARD_REPORT")
    if path:
        Path(path).write_text(json.dumps({"raw": _raw, "late_plugins": sorted(set(_late))}, indent=1), encoding="utf-8")


def _check_plugins(config):
    for p in config.pluginmanager.get_plugins():
        if id(p) in _plugins_at_start:
            continue
        name = config.pluginmanager.get_name(p) or repr(p)
        # pytest registers conftest modules and its own session objects after start; those are expected
        if name.endswith("conftest.py") or name in {"session", "funcmanage", "collectionstarted"} or \
                name.startswith(("<_pytest", "_pytest", "<Session", "lfplugin", "nfplugin")):
            continue
        _late.append(name)


def scan(paths) -> list[str]:
    """Static check of test code by syntax tree (string literals do not count)."""
    out = []
    for f in paths:
        f = Path(f)
        try:
            tree = ast.parse(f.read_text(encoding="utf-8"))
        except SyntaxError as e:
            out.append(f"{f}: does not parse: {e}")
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                bad = [a.name for a in n.names if a.name.split(".")[0] in FORBIDDEN_MODULES]
            elif isinstance(n, ast.ImportFrom) and n.module == "gate_guard":
                # the pure checks may be imported (the gate's own test does); the plugin's state never
                bad = [f"gate_guard.{a.name}" for a in n.names if a.name not in PURE]
            elif isinstance(n, ast.ImportFrom):
                bad = [n.module] if n.module and n.module.split(".")[0] in FORBIDDEN_MODULES else []
            elif isinstance(n, ast.Attribute) and n.attr in FORBIDDEN_ATTRS:
                bad = [f".{n.attr}"]
            elif isinstance(n, ast.FunctionDef) and n.name.startswith("pytest_") and \
                    not (f.name == "conftest.py" and n.name in ALLOWED_CONFTEST_HOOKS):
                bad = [f"def {n.name}"]
            else:
                bad = []
            out += [f"{f.name}:{getattr(n, 'lineno', '?')}: {b} is not allowed in test code" for b in bad]
    return out


def assert_map(source: str) -> dict[str, list[str]]:
    """Every test function's assert expressions, normalised, for the regression guard."""
    tree = ast.parse(source)
    return {fn.name: [ast.dump(a.test, annotate_fields=False) for a in ast.walk(fn) if isinstance(a, ast.Assert)]
            for fn in tree.body if isinstance(fn, ast.FunctionDef) and fn.name.startswith("test_")}


def changed_asserts(base_source: str, head_source: str) -> list[str]:
    """Tests whose existing asserts were removed or changed (added asserts are fine)."""
    was, now = assert_map(base_source), assert_map(head_source)
    out = []
    for name, asserts in was.items():
        if name not in now:
            continue   # a removed test is caught by the count guard
        missing = [a for a in asserts if a not in now[name]]
        if missing:
            out.append(f"{name}: {len(missing)} assert(s) changed or removed")
    return out
