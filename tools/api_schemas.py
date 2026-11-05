"""Every lab manifest against the schema the ring's API server applies.

The gate checked what the tree means but never that a ring's API server accepts it: a CertificateRequestPolicy with a
field approver-policy does not have (commonName.values) can pass every other test and still fail Flux's dry run.
This closes that class of error at the gate, offline:

  capture DIR   read the OpenAPI v3 documents a ring served (one file per group-version, from
                `kubectl get --raw /openapi/v3/...`) and keep only the schemas the lab tree's kinds
                reach, in frameworks/k8s-api/schemas.json, with the chart and Flux versions they were captured at
  check         (default; in the fast checks) validate every document in gitops/lab against its kind's schema the way
                the API server's strict field validation does: unknown fields are errors unless the schema preserves
                them, required fields must be there, types must match. Flux's postBuild defaults (${var:=default}) are
                substituted first. It fails on a kind without a schema that is not listed in UNCHECKED, and on a chart
                or Flux version that differs from the one the schemas were captured at (capture again from a ring).

Usage: python tools/api_schemas.py [check | capture DIR]
"""
from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parent.parent
LAB = ROOT / "gitops" / "lab"
OUT = ROOT / "frameworks" / "k8s-api" / "schemas.json"
# kinds that never reach the API server: kustomize's own files are read by the client
CLIENT_SIDE = {("kustomize.config.k8s.io/v1beta1", "Kustomization"), ("kustomize.config.k8s.io/v1alpha1", "Component")}
# kinds the API serves but the check cannot take from a capture, each with its reason (none today)
UNCHECKED: dict[tuple[str, str], str] = {}
SUBST = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:=([^}]*))?\}")


def versions(root: Path = ROOT) -> dict:
    """What the API's schemas depend on: the locked charts and the Flux release."""
    charts = yaml.safe_load((root / "gitops/lab/chart-lock.yaml").read_text(encoding="utf-8"))["charts"]
    flux = yaml.safe_load((root / "gitops/lab/flux-lock.yaml").read_text(encoding="utf-8"))["flux_version"]
    return {"charts": {c["name"]: c["version"] for c in charts}, "flux": flux}


def docs(root: Path = ROOT):
    for f in sorted((root / "gitops" / "lab").rglob("*.yaml")):
        text = f.read_text(encoding="utf-8")
        text = SUBST.sub(lambda m: m.group(3) if m.group(3) is not None else "placeholder", text)
        for d in yaml.safe_load_all(text):
            if isinstance(d, dict) and "kind" in d and "apiVersion" in d:
                yield f.relative_to(root).as_posix(), d


def gvk_name(api_version: str, kind: str) -> str:
    """The x-kubernetes-group-version-kind key the API server uses."""
    group, _, version = api_version.rpartition("/")
    return f"{group}|{version}|{kind}"


def capture(src: Path, root: Path = ROOT) -> dict:
    """Prune the ring's OpenAPI documents to what the tree's kinds reach."""
    schemas, by_gvk = {}, {}
    for f in sorted(src.glob("*.json")):
        doc = json.loads(f.read_text(encoding="utf-8"))
        for name, s in doc.get("components", {}).get("schemas", {}).items():
            schemas[name] = s
            for g in s.get("x-kubernetes-group-version-kind", []):
                by_gvk[f"{g.get('group', '')}|{g['version']}|{g['kind']}"] = name
    wanted = {gvk_name(d["apiVersion"], d["kind"]) for _, d in docs(root)
              if (d["apiVersion"], d["kind"]) not in CLIENT_SIDE}
    kinds = {k: by_gvk[k] for k in sorted(wanted) if k in by_gvk}
    keep, todo = set(), list(kinds.values())
    while todo:
        n = todo.pop()
        if n in keep or n not in schemas:
            continue
        keep.add(n)
        todo += re.findall(r'"#/components/schemas/([^"]+)"', json.dumps(schemas[n]))
    def bare(s):   # validation needs no prose: descriptions are dropped (smaller, and upstream text stays upstream)
        if isinstance(s, dict):
            return {k: bare(v) for k, v in s.items() if k != "description"}
        return [bare(x) for x in s] if isinstance(s, list) else s
    out = {"captured": versions(root), "kinds": kinds, "schemas": {n: bare(schemas[n]) for n in sorted(keep)}}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(out, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")
    return out


JUNCTORS = ("oneOf", "anyOf", "allOf", "not")


def strict(s, junctor: bool = False):
    """The API server's strict field validation: an object with declared properties takes no others, unless the schema
    preserves unknown fields; OpenAPI's nullable allows null. Inside oneOf, anyOf, allOf and not, a structural schema's
    properties only constrain values and declare no fields (Kubernetes structural schemas), so they stay open there."""
    if isinstance(s, list):
        return [strict(x, junctor) for x in s]
    if not isinstance(s, dict):
        return s
    s = {k: strict(v, junctor or k in JUNCTORS) if k != "properties" else {p: strict(v2) for p, v2 in v.items()}
         for k, v in s.items()}
    if not junctor and "properties" in s and "additionalProperties" not in s and not s.get("x-kubernetes-preserve-unknown-fields"):
        s["additionalProperties"] = False
    if s.get("nullable") and "type" in s:
        s["type"] = [s["type"], "null"] if isinstance(s["type"], str) else s["type"] + ["null"]
    if s.get("x-kubernetes-int-or-string"):
        s.pop("type", None)
    if "allOf" in s and len(s["allOf"]) == 1 and "$ref" in s["allOf"][0] and "properties" not in s:
        s.update(s.pop("allOf")[0])
    return s


def check(root: Path = ROOT) -> list[str]:
    path = root / "frameworks" / "k8s-api" / "schemas.json"
    if not path.exists():
        return ["frameworks/k8s-api/schemas.json is missing: capture it from a ring (api_schemas.py capture)"]
    cap = json.loads(path.read_text(encoding="utf-8"))
    errs = []
    now = versions(root)
    for name, v in now["charts"].items():
        if cap["captured"]["charts"].get(name) != v:
            errs.append(f"chart {name} is {v} in the lock but the schemas were captured at {cap['captured']['charts'].get(name)}: capture again from a ring")
    if cap["captured"]["flux"] != now["flux"]:
        errs.append(f"Flux is {now['flux']} but the schemas were captured at {cap['captured']['flux']}: capture again")
    resource = {"components": {"schemas": {n: strict(s) for n, s in cap["schemas"].items()}}}
    for rel, d in docs(root):
        key = (d["apiVersion"], d["kind"])
        if key in CLIENT_SIDE or key in UNCHECKED:
            continue
        name = cap["kinds"].get(gvk_name(*key))
        if not name:
            errs.append(f"{rel}: {key[0]} {key[1]} has no captured schema (capture from a ring that serves it, or list it in UNCHECKED with a reason)")
            continue
        schema = dict(resource, **{"$ref": f"#/components/schemas/{name}"})
        v = jsonschema.Draft4Validator(schema)
        for e in sorted(v.iter_errors(copy.deepcopy(d)), key=lambda e: list(e.absolute_path)):
            where = "/".join(str(p) for p in e.absolute_path) or "(root)"
            errs.append(f"{rel}: {key[1]} {d.get('metadata', {}).get('name', '?')}: {where}: {e.message[:200]}")
    return errs


def main(argv: list[str]) -> int:
    if argv[:1] == ["capture"]:
        out = capture(Path(argv[1]))
        print(f"captured {len(out['kinds'])} kinds, {len(out['schemas'])} schemas")
        return 0
    errs = check()
    for e in errs:
        print(f"FAIL {e}")
    print(f"api schemas: {len(errs)} error(s)")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
