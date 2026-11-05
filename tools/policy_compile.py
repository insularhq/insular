"""Compile the policy packs into an OPA bundle (ADR-0092): rules as data, the generic evaluator policy/vdh/*.rego,
the band floors, and a manifest with the model revision. The bundle is what gets signed and shipped
(policies/master-protection.yaml anti_rollback: monotonic version and expiry are added at release).

Usage: python tools/policy_compile.py [--out build/opa-bundle] [--check]   (--check runs opa test on the evaluator)
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))


def _norm(v):
    if isinstance(v, date):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _norm(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_norm(x) for x in v]
    return v


def bundle_data() -> dict:
    from policy_engine import load as pload
    model, rules = pload()
    clean = [_norm({k: v for k, v in r.items() if k != "pack"}) | {"pack": r.get("pack")} for r in rules]
    # the autonomy matrix for the decision inbox (ADR-0169): the level of an act comes from here, never from the inbox
    auto = yaml.safe_load((ROOT / "governance" / "autonomy.yaml").read_text(encoding="utf-8"))
    autonomy = {"actions": auto["actions"], "max_autonomy": auto["max_autonomy"]}
    return {"vdh": {"rules": clean, "band_floor": model["band_enforcement"]["floor"], "autonomy": autonomy}}


def engine_policy() -> dict[str, str]:
    """The pinned KeyClerk engine's Rego (package keyclerk.*, ADR-0176), file name -> text."""
    sys.path.insert(0, str(ROOT / "tools"))
    import keyclerk_config
    keyclerk_config.setup()
    from keyclerk import config
    return config.policy_files()


def build(out: Path) -> Path:
    if out.exists():
        shutil.rmtree(out)
    (out / "vdh").mkdir(parents=True)
    (out / "keyclerk").mkdir()
    for name, text in engine_policy().items():
        (out / "keyclerk" / name).write_text(text, encoding="utf-8", newline=chr(10))
    (out / "data.json").write_text(json.dumps(bundle_data(), sort_keys=True, indent=1), encoding="utf-8")
    for f in (ROOT / "policy" / "vdh").glob("*.rego"):
        if not f.name.endswith("_test.rego"):
            shutil.copy(f, out / "vdh" / f.name)
    rev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip() or "unknown"
    (out / ".manifest").write_text(json.dumps({"revision": rev, "roots": ["vdh", "keyclerk"]}), encoding="utf-8")
    return out


GITOPS = ROOT / "gitops" / "lab" / "pdp" / "bundle"


def gitops_files() -> dict[str, str]:
    """The bundle as the lab PDP loads it from a ConfigMap (flat: data.json plus the evaluator), with a revision
    derived from the content so the committed copy is checkable (ADR-0101)."""
    import hashlib
    nl = chr(10)
    files = {"data.json": json.dumps(bundle_data(), sort_keys=True, indent=1) + nl}
    for f in sorted((ROOT / "policy" / "vdh").glob("*.rego")):
        if not f.name.endswith("_test.rego"):
            files[f.name] = f.read_text(encoding="utf-8").replace(chr(13) + nl, nl)
    for name, text in engine_policy().items():   # the engine's Rego, flat beside this deployment's (ADR-0176)
        files[name] = text.replace(chr(13) + nl, nl)
    digest = hashlib.sha256("".join(k + v for k, v in sorted(files.items())).encode()).hexdigest()
    files["revision.txt"] = f"sha256:{digest}" + nl
    return files


def write_gitops() -> None:
    GITOPS.mkdir(parents=True, exist_ok=True)
    for name, text in gitops_files().items():
        (GITOPS / name).write_text(text, encoding="utf-8", newline=chr(10))


def gitops_stale() -> list[str]:
    want = gitops_files()
    have = {f.name: f.read_text(encoding="utf-8") for f in GITOPS.glob("*")} if GITOPS.exists() else {}
    return sorted(n for n in set(want) | set(have) if want.get(n) != have.get(n))


def opa() -> str | None:
    return shutil.which("opa")


def evaluate(bundle: Path, context: dict) -> dict:
    """Evaluate data.vdh.decide.result with OPA for one context (used by the differential test)."""
    r = subprocess.run([opa(), "eval", "-b", str(bundle), "-I", "-f", "json", "data.vdh.decide.result"],
                       input=json.dumps({"context": context}), capture_output=True, text=True, check=True)
    res = json.loads(r.stdout)["result"]
    return res[0]["expressions"][0]["value"] if res else {}


if __name__ == "__main__" and "--gitops" in sys.argv:
    if "--check" in sys.argv:
        stale = gitops_stale()
        print("gitops/lab/pdp/bundle is stale: " + ", ".join(stale) + " (run python tools/policy_compile.py --gitops)" if stale else "gitops/lab/pdp/bundle current")
        sys.exit(1 if stale else 0)
    write_gitops()
    print("gitops/lab/pdp/bundle written")
    sys.exit(0)

if __name__ == "__main__":
    out = Path(sys.argv[sys.argv.index("--out") + 1]) if "--out" in sys.argv else ROOT / "build" / "opa-bundle"
    b = build(out)
    print(f"bundle at {b.relative_to(ROOT) if b.is_relative_to(ROOT) else b}: {len(bundle_data()['vdh']['rules'])} rules")
    if "--check" in sys.argv:
        if not opa():
            print("ERROR opa not installed")
            sys.exit(1)
        r = subprocess.run([opa(), "test", str(ROOT / "policy"), "-v"], capture_output=True, text=True)
        print(r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr[-400:])
        sys.exit(r.returncode)
