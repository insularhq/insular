"""One canonical security label per unit, rendered into every standard format (ADR-0103).

From a data envelope (label, ring, purposes, tenant, assurance, completeness) and policies/security-labels.yaml this
module renders:
- spif(): the labelling policy as an XML SPIF (http://www.xmlspif.org/spif);
- stanag4774(): a confidentiality label (urn:nato:stanag:4774:confidentialitymetadatalabel:1:0);
- ess_encode() / ess_decode(): ESS security labels (RFC 2634) in DER, read leniently as BER;
- sio_label() / parse_sio_label(): the RFC 7444 mail header, folded, with RFC 2231 continuations;
- xep0258(): the XMPP <securitylabel/> element;
- matrix(): the Matrix event content field;
- stanag4778(): a metadata binding container that binds the label to the unit's digest.

Usage: python tools/security_labels.py   (checks the policy and writes nothing)
"""
from __future__ import annotations

import base64
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
NS4774 = "urn:nato:stanag:4774:confidentialitymetadatalabel:1:0"
NS4778 = "urn:nato:stanag:4778:bindinginformation:1:0"
NSSPIF = "http://www.xmlspif.org/spif"
NSXEP = "urn:xmpp:sec-label:0"
NSXEPESS = "urn:xmpp:sec-label:ess:0"
NSVDH = "urn:vdh:binding:1"
LABELS = ["Internal", "Sensitive", "Restricted"]
COLOURS = {"aqua", "black", "blue", "fuchsia", "gray", "green", "lime", "maroon", "navy", "olive", "purple", "red",
           "silver", "teal", "white", "yellow", "orange"}


def policy() -> dict:
    return yaml.safe_load((ROOT / "policies" / "security-labels.yaml").read_text(encoding="utf-8"))


# ---- ESS security label (RFC 2634): DER out, BER in --------------------------------------------------------------

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def _oid(dotted: str) -> bytes:
    a = [int(x) for x in dotted.split(".")]
    out = bytearray()
    for i, v in enumerate([40 * a[0] + a[1]] + a[2:]):
        chunk = [v & 0x7F]
        v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(chunk))
    return bytes(out)


def _oid_str(b: bytes) -> str:
    vals, v = [], 0
    for x in b:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            vals.append(v)
            v = 0
    first = vals[0]
    head = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    return ".".join(str(x) for x in head + vals[1:])


def _int(n: int) -> bytes:
    b = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True)
    return b


def ess_encode(policy_oid: str, classification: int | None = None, privacy_mark: str | None = None) -> str:
    """Base64 of the DER ESSSecurityLabel: a SET whose components are ordered by tag (INTEGER, OID, UTF8String)."""
    parts = []
    if classification is not None:
        parts.append(_tlv(0x02, _int(classification)))
    parts.append(_tlv(0x06, _oid(policy_oid)))
    if privacy_mark is not None:
        parts.append(_tlv(0x0C, privacy_mark.encode("utf-8")))
    return base64.b64encode(_tlv(0x31, b"".join(sorted(parts, key=lambda p: p[0])))).decode()


def ess_decode(b64: str) -> dict:
    """Read an ESSSecurityLabel in any BER order: policy, classification, privacy mark, raw categories."""
    data = base64.b64decode("".join(b64.split()))
    if data[0] != 0x31:
        raise ValueError("not an ESSSecurityLabel (expected a SET)")

    def read(buf, i):
        tag, i = buf[i], i + 1
        n = buf[i]
        i += 1
        if n & 0x80:
            k = n & 0x7F
            n, i = int.from_bytes(buf[i:i + k], "big"), i + k
        return tag, buf[i:i + n], i + n
    _, body, _ = read(data, 0)
    out, i = {"policy": None, "classification": None, "privacy_mark": None, "categories": None}, 0
    while i < len(body):
        tag, val, i = read(body, i)
        if tag == 0x06:
            out["policy"] = _oid_str(val)
        elif tag == 0x02:
            out["classification"] = int.from_bytes(val, "big", signed=True)
        elif tag in (0x0C, 0x13):
            out["privacy_mark"] = val.decode("utf-8")
        elif tag == 0x31:
            out["categories"] = base64.b64encode(val).decode()
    return out


# ---- the canonical label from an envelope ------------------------------------------------------------------------

def canonical(env: dict, tenant: str = "vdhome", rings: list[str] | None = None) -> dict:
    p = policy()
    rings = rings or ["host", "site", "tenant", "federation", "public"]
    c = p["classifications"][env["label"]]
    return {"policy": p["policy"], "classification": c, "label": env["label"],
            "categories": [
                ("PERMISSIVE", "Releasable Within", rings[: rings.index(env["releasable_to"]) + 1]),
                ("PERMISSIVE", "Purpose", list(env["purposes"])),
                ("RESTRICTIVE", "Tenant", [tenant]),
                ("INFORMATIVE", "Assurance", [env.get("assurance", "signed")]),
                ("INFORMATIVE", "Provenance", ["complete" if env.get("complete", True) else "incomplete"])],
            "created": f"{env.get('recorded', '2026-10-10')}T00:00:00Z",
            "review": f"{env['valid_until']}T00:00:00Z" if env.get("valid_until") else None}


def stanag4774(lab: dict, element: str = "ConfidentialityLabel") -> ET.Element:
    root = ET.Element(f"{{{NS4774}}}{element}", {"ReviewDateTime": lab["review"]} if lab["review"] else {})
    info = ET.SubElement(root, f"{{{NS4774}}}ConfidentialityInformation")
    ET.SubElement(info, f"{{{NS4774}}}PolicyIdentifier", {"URI": f"urn:oid:{lab['policy']['oid']}"}).text = lab["policy"]["name"]
    ET.SubElement(info, f"{{{NS4774}}}Classification").text = lab["classification"]["name"]
    for typ, tag, values in lab["categories"]:
        if not values:
            continue
        cat = ET.SubElement(info, f"{{{NS4774}}}Category", {"Type": typ, "TagName": tag})
        for v in values:
            ET.SubElement(cat, f"{{{NS4774}}}GenericValue").text = str(v)
    ET.SubElement(root, f"{{{NS4774}}}CreationDateTime").text = lab["created"]
    return root


def xml(el: ET.Element) -> str:
    ET.register_namespace("slab", NS4774)
    ET.register_namespace("mb", NS4778)
    ET.register_namespace("spif", NSSPIF)
    ET.register_namespace("vdh", NSVDH)
    return ET.tostring(el, encoding="unicode")


def parse_4774(text: str) -> dict:
    root = ET.fromstring(text)
    info = root.find(f"{{{NS4774}}}ConfidentialityInformation")
    return {"policy": info.findtext(f"{{{NS4774}}}PolicyIdentifier"),
            "policy_uri": info.find(f"{{{NS4774}}}PolicyIdentifier").get("URI"),
            "classification": info.findtext(f"{{{NS4774}}}Classification"),
            "categories": [(c.get("Type"), c.get("TagName"), [g.text for g in c.findall(f"{{{NS4774}}}GenericValue")])
                           for c in info.findall(f"{{{NS4774}}}Category")],
            "created": root.findtext(f"{{{NS4774}}}CreationDateTime")}


def ess_for(lab: dict) -> str:
    within = next(v for t, tag, v in lab["categories"] if tag == "Releasable Within")
    purpose = next(v for t, tag, v in lab["categories"] if tag == "Purpose")
    mark = f"{lab['classification']['marking']} WITHIN {within[-1].upper()}" + (f" FOR {', '.join(purpose).upper()}" if purpose else "")
    return ess_encode(lab["policy"]["oid"], lab["classification"]["lacv"], mark)


# ---- RFC 7444 SIO-Label ------------------------------------------------------------------------------------------

def sio_label(lab: dict, kind: str = ":xml", width: int = 60) -> str:
    """The header, folded with CRLF+space between parameters; a long label value uses RFC 2231 continuations."""
    c = lab["classification"]
    assert c["fgcolor"] in COLOURS and c["bgcolor"] in COLOURS
    value = base64.b64encode(xml(stanag4774(lab)).encode()).decode() if kind == ":xml" else ess_for(lab)
    params = [f'marking="{c["marking"]}"', f"fgcolor={c['fgcolor']}", f"bgcolor={c['bgcolor']}", f'type="{kind}"']
    if len(value) <= width:
        params.append(f'label="{value}"')
    else:
        params += [f'label*{i}="{value[j:j + width]}"' for i, j in enumerate(range(0, len(value), width))]
    return "SIO-Label: " + ";\r\n ".join(params)


def parse_sio_label(header: str) -> dict:
    text = header.split(":", 1)[1].replace("\r\n ", " ").replace("\r\n\t", " ")
    params, cur, quoted = [], "", False
    for ch in text:
        if ch == '"':
            quoted = not quoted
        if ch == ";" and not quoted:
            params.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        params.append(cur.strip())
    out, parts = {}, {}
    for p in params:
        k, v = p.split("=", 1)
        v = v.strip().strip('"')
        if "*" in k:
            name, idx = k.split("*", 1)
            parts.setdefault(name, {})[int(idx)] = v
        else:
            out[k.strip()] = v
    for name, chunks in parts.items():
        out[name] = "".join(chunks[i] for i in sorted(chunks))
    return out


# ---- XEP-0258, Matrix, STANAG 4778, SPIF -------------------------------------------------------------------------

def xep0258(lab: dict) -> str:
    c = lab["classification"]
    root = ET.Element(f"{{{NSXEP}}}securitylabel")
    ET.SubElement(root, f"{{{NSXEP}}}displaymarking", {"fgcolor": c["fgcolor"], "bgcolor": c["bgcolor"]}).text = c["marking"]
    ET.SubElement(root, f"{{{NSXEP}}}label").append(stanag4774(lab))
    eq = ET.SubElement(root, f"{{{NSXEP}}}equivalentlabel")
    ET.SubElement(eq, f"{{{NSXEPESS}}}esssecuritylabel").text = ess_for(lab)
    ET.register_namespace("", NSXEP)
    return xml(root)


def matrix(lab: dict) -> dict:
    c = lab["classification"]
    return {policy()["renderings"]["matrix"]["field"]: {
        "marking": c["marking"], "fgcolor": c["fgcolor"], "bgcolor": c["bgcolor"],
        "stanag4774": xml(stanag4774(lab)), "ess": ess_for(lab)}}


def stanag4778(lab: dict, env: dict) -> str:
    root = ET.Element(f"{{{NS4778}}}MetadataBindingContainer")
    mb = ET.SubElement(root, f"{{{NS4778}}}MetadataBinding")
    ET.SubElement(mb, f"{{{NS4778}}}Metadata").append(stanag4774(lab, "originatorConfidentialityLabel"))
    ET.SubElement(mb, f"{{{NS4778}}}DataReference", {"URI": f"urn:vdh:unit:{env['digest']}"})
    sig = env["chain"][-1].get("signature")
    ET.SubElement(root, f"{{{NSVDH}}}EnvelopeBinding", {"digest": env["digest"], **({"signature": sig} if sig else {})})
    return xml(root)


def spif(today: str = "2026-10-10") -> str:
    p = policy()
    sys.path.insert(0, str(ROOT / "tools"))
    dp = yaml.safe_load((ROOT / "platform" / "data-platform.yaml").read_text(encoding="utf-8"))
    pv = yaml.safe_load((ROOT / "policies" / "data-provenance.yaml").read_text(encoding="utf-8"))
    values = {"rings": pv["rings"]["order"], "purposes": sorted({x for q in dp["products"].values() for x in q["purposes"]}),
              "tenants": ["vdhome"], "assurance": pv["assurance"]["order"], }
    oid = p["policy"]["oid"]
    # Open XML SPIF 3.0 (validated against http://www.xmlspif.org/schema/xmlspif.xsd): the policy id and every
    # classification and tag value carry markingData; SPIF has no informative tag type, so STANAG 4774 INFORMATIVE
    # categories map to the free-form tagType7.
    root = ET.Element(f"{{{NSSPIF}}}SPIF", {"schemaVersion": "3.0", "version": str(p["policy"]["version"]),
                                           "creationDate": today.replace("-", "") + "000000Z",
                                           "originatorDN": "CN=VDHome,O=VDHome,C=BE",
                                           "privilegeId": f"{oid}.6", "rbacId": f"{oid}.7"})
    pid = ET.SubElement(root, f"{{{NSSPIF}}}securityPolicyId", {"name": p["policy"]["name"], "id": oid})
    ET.SubElement(pid, f"{{{NSSPIF}}}markingData", {"phrase": p["policy"]["name"]})
    cls = ET.SubElement(root, f"{{{NSSPIF}}}securityClassifications")
    for lab in LABELS:
        c = p["classifications"][lab]
        sc = ET.SubElement(cls, f"{{{NSSPIF}}}securityClassification", {"name": c["name"], "lacv": str(c["lacv"]),
                           "hierarchy": str(c["hierarchy"]), "fgcolor": c["fgcolor"], "bgcolor": c["bgcolor"]})
        ET.SubElement(sc, f"{{{NSSPIF}}}markingData", {"phrase": c["marking"]})
    sets = ET.SubElement(root, f"{{{NSSPIF}}}securityCategoryTagSets")
    kind = {"PERMISSIVE": "permissive", "RESTRICTIVE": "restrictive", "INFORMATIVE": "tagType7"}
    for key, cat in p["categories"].items():
        ts = ET.SubElement(sets, f"{{{NSSPIF}}}securityCategoryTagSet", {"name": cat["tag"], "id": f"{oid}.{cat['arc']}"})
        tag = ET.SubElement(ts, f"{{{NSSPIF}}}securityCategoryTag", {"name": cat["tag"], "tagType": kind[cat["type"]]})
        vals = values.get(cat["values"], cat["values"]) if isinstance(cat["values"], str) else cat["values"]
        for i, v in enumerate(vals, 1):
            tc = ET.SubElement(tag, f"{{{NSSPIF}}}tagCategory", {"name": str(v), "lacv": str(i)})
            ET.SubElement(tc, f"{{{NSSPIF}}}markingData", {"phrase": str(v).upper()})
    return xml(root)


def check() -> list[str]:
    p, errs = policy(), []
    order = [p["classifications"][x]["hierarchy"] for x in LABELS]
    if order != sorted(order) or len(set(order)) != len(order):
        errs.append("classification hierarchy must rise strictly from Internal to Restricted")
    for lab, c in p["classifications"].items():
        if c["fgcolor"] not in COLOURS or c["bgcolor"] not in COLOURS:
            errs.append(f"{lab}: colours must be RFC 7444 named colours")
        if not c["marking"].startswith(p["policy"]["name"] + " "):
            errs.append(f"{lab}: the display marking must name the policy, so it is never mistaken for another policy's marking")
    if not p["policy"]["oid"].startswith("2.25."):
        errs.append("policy oid: use the X.667 UUID arc or a registered arc")
    types = {c["type"] for c in p["categories"].values()}
    if types - {"PERMISSIVE", "RESTRICTIVE", "INFORMATIVE"}:
        errs.append("category types must be the STANAG 4774 types")
    return errs


if __name__ == "__main__":
    problems = check()
    print(f"policy {policy()['policy']['name']} {policy()['policy']['oid']}, {len(policy()['categories'])} category tag sets")
    for x in problems:
        print("ERROR", x)
    sys.exit(1 if problems else 0)
