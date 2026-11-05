"""Image pins in the lab GitOps tree.

Every image the lab runs is pinned by digest, and nothing in the tree can retarget a pinned image: no `.yml` file
outside the checks, no `image:` value without `@sha256:` at any depth (multi-line or nested), no Helm values that
override an image repository or tag, and no `images:` entry (kustomization or Flux post-renderer) that carries
`newName` or `newTag` or lacks a digest. The rendered check (every image a chart actually renders) is the lab digest
check and, later, CI rendering.

Usage: python tools/pins.py [path]   (default gitops/lab; exit 1 with the reasons when anything is unpinned)
       python tools/pins.py --expected [path]   (the "name digest" lines the lab digest check compares against)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ROOT = Path(__file__).resolve().parent.parent


def _walk(node, path=()):
    if isinstance(node, dict):
        for k, v in node.items():
            yield path + (k,), k, v
            yield from _walk(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, path + (i,))


def _images_list(entries, where: str) -> list[str]:
    out = []
    for e in entries or []:
        if not isinstance(e, dict):
            out.append(f"{where}: an images entry that is not a mapping")
            continue
        if "newName" in e or "newTag" in e:
            out.append(f"{where}: images entry for {e.get('name')} retargets it (newName/newTag)")
        if not DIGEST.match(str(e.get("digest", ""))):
            out.append(f"{where}: images entry for {e.get('name')} has no sha256 digest")
    return out


def _patch_image_envs(release: dict) -> list[tuple[str, str | None]]:
    """(env name, value) for every `*IMAGE` env a post-renderer patch sets: images a component injects at runtime,
    such as the Barman plugin's sidecar."""
    out = []
    for pr in release["spec"].get("postRenderers", []):
        for p in pr.get("kustomize", {}).get("patches", []):
            body = p.get("patch")
            for doc in yaml.safe_load_all(body) if isinstance(body, str) else []:
                for _, k, v in _walk(doc):
                    if k == "env" and isinstance(v, list):
                        out += [(e.get("name"), e.get("value")) for e in v
                                if isinstance(e, dict) and str(e.get("name", "")).endswith("IMAGE")]
    return out


def check(base: Path | str | None = None) -> list[str]:
    base = Path(base) if base else ROOT / "gitops" / "lab"
    errs: list[str] = []
    for f in sorted(base.rglob("*.yml")):
        errs.append(f"{f.relative_to(base)}: .yml files are not allowed (the pins are checked on .yaml)")
    seen_release = 0
    for f in sorted(base.rglob("*.yaml")):
        if f.name.endswith("-lock.yaml"):
            continue   # locks are checked below, they are not Kubernetes resources
        rel = str(f.relative_to(base))
        for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")):
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind")
            if kind == "Kustomization" and doc.get("apiVersion", "").startswith("kustomize.config.k8s.io"):
                errs += _images_list(doc.get("images"), rel)
            if kind == "HelmRelease":
                for name, value in _patch_image_envs(doc):
                    if not value or "@sha256:" not in value:
                        errs.append(f"{rel}: HelmRelease {doc['metadata']['name']} patch sets {name} without a digest")
                seen_release += 1
                imgs = [i for pr in doc["spec"].get("postRenderers", []) for i in pr.get("kustomize", {}).get("images", [])]
                if not imgs:
                    errs.append(f"{rel}: HelmRelease {doc['metadata']['name']} pins no image")
                errs += _images_list(imgs, rel)
                for p, k, v in _walk(doc["spec"].get("values", {})):
                    if k in ("repository", "registry", "tag", "image", "digest"):
                        errs.append(f"{rel}: HelmRelease {doc['metadata']['name']} values override an image ({'.'.join(map(str, p))})")
            for p, k, v in _walk(doc):
                if k == "image" and isinstance(v, str) and "@sha256:" not in v:
                    errs.append(f"{rel}: image {v} is not pinned by digest ({'.'.join(map(str, p))})")
                if k == "imageName" and isinstance(v, str) and "@sha256:" not in v:
                    errs.append(f"{rel}: imageName {v} is not pinned by digest")
    if seen_release == 0:
        errs.append("no HelmRelease found: the check is looking at the wrong tree")
    lock = base / "flux-lock.yaml"
    if not lock.exists():
        errs.append("flux-lock.yaml missing: Flux would be installed by tag")
    else:
        fl = yaml.safe_load(lock.read_text(encoding="utf-8"))
        names = {c["name"] for c in fl.get("controllers", [])}
        if names != {"source-controller", "kustomize-controller", "helm-controller", "notification-controller"}:
            errs.append(f"flux-lock.yaml: controllers {sorted(names)}")
        for c in fl.get("controllers", []):
            if not DIGEST.match(str(c.get("digest", ""))):
                errs.append(f"flux-lock.yaml: {c.get('name')} has no sha256 digest")
            if c.get("upstream_signature") != "verified":
                errs.append(f"flux-lock.yaml: {c.get('name')} digest not verified against the upstream signature")
    lock = base / "cilium-lock.yaml"   # the CNI no longer floats with the CLI's stable.txt
    if not lock.exists():
        errs.append("cilium-lock.yaml missing: Cilium would be installed from whatever the CLI considers stable")
    else:
        cl = yaml.safe_load(lock.read_text(encoding="utf-8"))
        if {i["name"] for i in cl.get("images", [])} != {"cilium", "operator-generic", "cilium-envoy"}:
            errs.append(f"cilium-lock.yaml: images {sorted(i['name'] for i in cl.get('images', []))}")
        for i in cl.get("images", []):
            if not DIGEST.match(str(i.get("digest", ""))):
                errs.append(f"cilium-lock.yaml: {i.get('name')} has no sha256 digest")
            if i.get("upstream_signature") != "verified":
                errs.append(f"cilium-lock.yaml: {i.get('name')} digest not verified against the upstream signature")
    return errs


def expected(base: Path | str | None = None) -> list[tuple[str, str]]:
    """The (image name, digest) pairs the lab must run, for the lab digest check: every image
    referenced by digest in the tree, every post-renderer pin and every Flux controller in the lock."""
    base = Path(base) if base else ROOT / "gitops" / "lab"
    out: set[tuple[str, str]] = set()
    for f in sorted(base.rglob("*.yaml")):
        if f.name.endswith("-lock.yaml"):
            continue
        for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")):
            if not isinstance(doc, dict):
                continue
            for _, k, v in _walk(doc):
                if k in ("image", "imageName") and isinstance(v, str) and "@sha256:" in v:
                    name, dg = v.split("@", 1)
                    out.add((name.rsplit(":", 1)[0] if ":" in name.split("/")[-1] else name, dg))
            if doc.get("kind") == "HelmRelease":
                for pr in doc["spec"].get("postRenderers", []):
                    for i in pr.get("kustomize", {}).get("images", []):
                        out.add((i["name"], i["digest"]))
                for _, value in _patch_image_envs(doc):
                    if value and "@sha256:" in value:
                        out.add(tuple(value.split("@", 1)))
    lock = base / "flux-lock.yaml"
    if lock.exists():
        for c in yaml.safe_load(lock.read_text(encoding="utf-8"))["controllers"]:
            out.add((c["image"], c["digest"]))
    lock = base / "cilium-lock.yaml"
    if lock.exists():
        for i in yaml.safe_load(lock.read_text(encoding="utf-8"))["images"]:
            out.add((i["image"], i["digest"]))
    return sorted(out)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--expected":
        # LF on every platform: the lab reads this file
        sys.stdout.buffer.write("".join(f"{n} {d}\n" for n, d in expected(sys.argv[2] if len(sys.argv) > 2 else None)).encode())
        sys.exit(0)
    problems = check(sys.argv[1] if len(sys.argv) > 1 else None)
    print("\n".join(problems) or "all lab images pinned by digest; nothing retargets them")
    sys.exit(1 if problems else 0)
