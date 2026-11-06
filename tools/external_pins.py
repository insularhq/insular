"""External pins and the obligations they must keep.

Every external body of code or rules this model relies on is pinned by content in frameworks/external-pins.yaml:
- vendored files (FTEF): each file's sha256 matches the pin; with the upstream checkout present, each file also equals
  the upstream file at the pinned commit;
- packages (the KeyClerk engine): the installed version is the pinned tag, and its source is the pinned commit (an
  editable checkout at that commit with a clean tree, or a pip install whose recorded commit is the pinned one).
Each pin names an obligations register (conformance/*.yaml): Insular's checks and balances, each bound to tests in this
repository. Every bound test must exist, must not be skipped, and runs in the gate against the pinned version.

Usage: python tools/external_pins.py [--upstream]
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PINS = ROOT / "frameworks" / "external-pins.yaml"


def pins() -> list[dict]:
    return yaml.safe_load(PINS.read_text(encoding="utf-8"))["pins"]


def pin(name: str) -> dict:
    return next(p for p in pins() if p["name"] == name)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _test_names() -> dict[str, str]:
    """test function or class name -> file, for every test in tests/."""
    out = {}
    for f in (ROOT / "tests").glob("test_*.py"):
        text = f.read_text(encoding="utf-8")
        for m in re.finditer(r"^(?:def (test_\w+)|class (\w+)\b)", text, re.M):
            out[m.group(1) or m.group(2)] = f.name
    return out


def _skipped(name: str, file: str) -> bool:
    text = (ROOT / "tests" / file).read_text(encoding="utf-8")
    m = re.search(rf"((?:^@.*\n)*)^def {name}\(", text, re.M)
    body = text[m.end():m.end() + 400] if m else ""
    return bool(m and ("skip" in m.group(1) or re.search(r"pytest\.skip\(", body.split("\ndef ", 1)[0])))


def check_vendored(p: dict, upstream: bool) -> list[str]:
    errs = []
    for local, spec in p["files"].items():
        f = ROOT / local
        if not f.exists():
            errs.append(f"{p['name']}: {local} missing")
            continue
        if _sha(f) != spec["sha256"]:
            errs.append(f"{p['name']}: {local} differs from its pin (sha256)")
        if upstream:
            co = (ROOT / p["upstream_checkout"]).resolve()
            r = subprocess.run(["git", "-C", str(co), "show", f"{p['commit']}:{spec['from']}"], capture_output=True)
            if r.returncode:
                errs.append(f"{p['name']}: upstream {spec['from']} at {p['commit'][:12]} not readable")
            elif hashlib.sha256(r.stdout).hexdigest() != spec["sha256"]:
                errs.append(f"{p['name']}: {local} differs from upstream {spec['from']} at {p['commit'][:12]}")
    return errs


def installed_source(name: str) -> tuple[str | None, str | None]:
    """(version, commit) of the installed package: from an editable checkout's git, or pip's recorded commit."""
    try:
        import importlib.metadata as md
        dist = md.distribution(name)
    except Exception:
        return None, None
    version = dist.version
    direct = dist.read_text("direct_url.json")
    if direct:
        d = json.loads(direct)
        if d.get("vcs_info", {}).get("commit_id"):
            return version, d["vcs_info"]["commit_id"]
        # a release archive installed by its hash (pip --require-hashes): the source is that hash, which the pin ties
        # to the tag's commit (wheel_sha256 in frameworks/external-pins.yaml)
        h = (d.get("archive_info") or {}).get("hashes", {}).get("sha256")
        if h:
            return version, f"sha256:{h}"
        if d.get("dir_info", {}).get("editable") and d.get("url", "").startswith("file:"):
            path = d["url"][len("file:"):].lstrip("/")
            path = path if re.match(r"^[A-Za-z]:", path) else "/" + path
            head = subprocess.run(["git", "-C", path, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            dirty = subprocess.run(["git", "-C", path, "status", "--porcelain", "--", "keyclerk", "pyproject.toml"],
                                   capture_output=True, text=True).stdout.strip()
            return version, head + ("+dirty" if dirty else "")
    return version, None


def check_package(p: dict) -> list[str]:
    version, commit = installed_source(p["name"])
    want = p["tag"].lstrip("v")
    errs = []
    if version != want:
        errs.append(f"{p['name']}: installed {version}, pinned {want}")
    # the pinned commit, or the release wheel built from it, installed by its hash (the public CI's way: pip cannot
    # hash-check a git install)
    wheel = f"sha256:{p['wheel_sha256']}" if p.get("wheel_sha256") else None
    if commit != p["commit"] and (wheel is None or commit != wheel):
        errs.append(f"{p['name']}: installed from {commit or 'an unknown source'}, pinned commit {p['commit'][:12]}")
    return errs + check_requirements(p)


def check_requirements(p: dict, root: Path = ROOT) -> list[str]:
    """The install line (requirements-<name>.txt) names the pinned commit, or the pinned release wheel: a re-pin that
    left it behind installed the old engine in CI (it still named 0.26.3's commit)."""
    f = root / f"requirements-{p['name']}.txt"
    if not f.exists():
        return []
    text = f.read_text(encoding="utf-8")
    if p["commit"] in text or (p.get("wheel_sha256") and p["wheel_sha256"] in text):
        return []
    return [f"{f.name} does not install the pinned {p['name']} {p['tag']} (commit {p['commit'][:12]}): update its line"]


def check_obligations(p: dict) -> list[str]:
    reg = yaml.safe_load((ROOT / p["obligations"]).read_text(encoding="utf-8"))
    names = _test_names()
    # a published copy holds a selection of the decision records and of the tests; the others are private (its README
    # says so), so there an obligation's private test or record is not missing
    published = (ROOT / "ci" / "exported-on.txt").exists()
    errs = []
    ids = [o["id"] for o in reg["obligations"]]
    errs += [f"{p['name']}: obligation id {i} appears twice" for i in set(ids) if ids.count(i) > 1]
    for o in reg["obligations"]:
        if not o.get("tests"):
            errs.append(f"{o['id']}: bound to no test")
        present = [t for t in o.get("tests", []) if t in names]
        if published and o.get("tests") and not present:
            errs.append(f"{o['id']}: none of its tests is in this copy, so nothing checks it")
        for t in o.get("tests", []):
            if t not in names:
                if not published:
                    errs.append(f"{o['id']}: test {t} does not exist")
            elif _skipped(t, names[t]):
                errs.append(f"{o['id']}: test {t} is skipped")
        src = o["source"].split()[0]
        if src.startswith("ADR-") and not published and not list((ROOT / "intent" / "decisions").glob(f"{src}-*.md")):
            errs.append(f"{o['id']}: source {src} does not exist")
    return errs


def main(argv: list[str]) -> int:
    errs = []
    for p in pins():
        errs += check_vendored(p, "--upstream" in argv) if p["kind"] == "vendored" else check_package(p)
        errs += check_obligations(p)
    for e in errs:
        print(f"external pins: {e}", file=sys.stderr)
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
