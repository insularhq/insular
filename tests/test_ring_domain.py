"""Every sandbox ring holds its own domain (platform/estate-roles.yaml): the lab tree names the ring's domain only as
the Flux variable ${ring_domain:=lab.vdh.test}, and every unit that names it substitutes it from the ring's settings."""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "gitops" / "lab"
VAR = "${ring_domain:=lab.vdh.test}"


def texts():
    for f in sorted(LAB.rglob("*")):
        if f.is_file() and f.suffix in {".yaml", ".json", ".toml", ".rego"}:
            yield f, f.read_text(encoding="utf-8")


def test_the_lab_domain_appears_only_as_the_rings_default():
    bad = []
    # the PDP's pane rule keeps the lab names as defaults for the policy tests; in the ring its data (ring.json) wins
    allowed = {LAB / "pdp" / "bundle" / "authz.rego"}
    for f, t in texts():
        if f in allowed:
            continue
        rest = t.replace(VAR, "")
        if "lab.vdh.test" in rest:
            bad.append(str(f.relative_to(ROOT)))
    assert not bad, f"the ring's domain written literally (use {VAR}): {bad}"


def ring_variable_texts():
    """Every text file of the tree that names a ring variable (${ring_...}), whatever its kind: the DNS unit's Knot
    configuration and zone files carry them in .conf and .zone files, which the yaml-only scan missed."""
    for f in sorted(LAB.rglob("*")):
        if f.is_file() and f.suffix not in {".png", ".svg", ".ico", ".woff2", ".pyc"}:
            try:
                t = f.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if "${ring_" in t:
                yield f, t


def test_every_unit_naming_the_domain_substitutes_it_from_the_ring_settings():
    units = {f.relative_to(LAB).parts[0] for f, t in ring_variable_texts() if len(f.relative_to(LAB).parts) > 1}
    assert units, "no unit names the ring's domain"
    assert "dns" in units, "the scan must see the DNS unit's Knot files (never vacuous)"
    for u in sorted(units - {"layer1-config", "components"}):
        # a unit is applied from layer1-config, or by an opt-in component
        (src,) = [p for p in [LAB / "layer1-config" / f"flux-kustomization-{u}.yaml"]
                  + sorted((LAB / "components").glob(f"*/flux-kustomization-{u}.yaml")) if p.exists()]
        k = yaml.safe_load(src.read_text(encoding="utf-8"))
        refs = k["spec"].get("postBuild", {}).get("substituteFrom", [])
        assert {"kind": "ConfigMap", "name": "ring-settings", "optional": True} in refs, f"{u}: no substituteFrom ring-settings"


def test_the_federation_zone_names_only_the_rings_domain_and_its_public_addresses():
    """The federation zone and its public secondary are configuration files Flux substitutes; besides
    the ring's domain they may name only the edge node's public addresses, each with a documentation-range default
    (RFC 5737, RFC 3849) that can never answer for a real host."""
    allowed = {VAR, "${ring_public_v4:=192.0.2.1}", "${ring_public_v6:=2001:db8::1}"}
    files = sorted((LAB / "dns" / "config-federation").glob("*"))
    assert {f.name for f in files} == {"knot.conf", "federation.zone", "edge.conf"}
    for f in files:
        text = f.read_text(encoding="utf-8")
        found = set(re.findall(r"\$\{[^}]*\}", text))
        assert found and found <= allowed, f"{f.name}: {found - allowed}"
        assert "lab.vdh.test" not in text.replace(VAR, "")


def test_the_harbor_class_rule_passes_its_rego_tests():
    """The Harbor's PDP policy in the tree (ADR-0151) and its unit tests, including the data-plane hosts of stage 5."""
    import shutil
    import subprocess
    opa = shutil.which("opa")
    assert opa, "opa must be installed (CI installs a pinned, checksummed binary)"
    h = LAB / "harbor"
    r = subprocess.run([opa, "test", str(h / "harbor.rego"), str(h / "harbor_test.rego"), str(h / "harbor_test_certs.rego"),
                        str(h / "data.json")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout[-800:]


