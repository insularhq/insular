"""Data provenance engine (ADR-0096).

- derive: a new envelope from verified inputs. Label is the high-water mark, raised once per lineage by aggregation.
  Ring is the narrowest, purposes intersect, the end is the earliest, originators are unioned, and one signed step is
  appended. Undeclared reads fail closed and small aggregates are refused.
- verify: recomputes every property from the product registry and the inputs, checks the digest over the whole
  envelope (a Merkle DAG through input digests), the read set and the Ed25519 step signatures.
- resolve: who answers for an identity. Attribution is not authority: machines resolve through acts_for, and lapsed
  or vacant principals resolve to the steward, then the governance board. A cycle is an error.
- route: an access or release request goes to the owners whose own restriction blocks it, plus the approvers for its
  ring, label, declassification and effective risk band. Self-approval is excluded across delegation.
- view: the chain is redacted beyond the tenant (per-envelope pseudonyms).
- Store: the lineage store, anchored to the transparency log (tools/provenance_log.py); fail_closed for lineage that
  cannot be verified. Oversight without content lives in tools/oversight.py.
- impact: the graph walked forward. A change marks dependents stale or tainted, and artefacts citing them follow.

Not to be confused with tools/provenance.py, which reports on the provenance of software components.
Usage: python tools/data_provenance.py   (checks the model: rings, principals, consumers, identity kinds)
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from datetime import date, timedelta
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
LABELS = ["Internal", "Sensitive", "Restricted"]
BANDS = ["green", "amber", "red", "black"]
LIVING = {"person-role", "board"}
DERIVED_FIELDS = ("label", "releasable_to", "purposes", "valid_until", "originators", "sources", "uplifted_by",
                  "assurance", "complete", "authored", "fidelity")
ASSURANCE = ["attested", "signed", "asserted", "transcribed", "unidentified"]   # strongest first (ADR-0099)


def _y(rel: str):
    return yaml.safe_load((ROOT / rel).read_text(encoding="utf-8"))


def load() -> dict:
    return {"pv": _y("policies/data-provenance.yaml"), "dp": _y("platform/data-platform.yaml"),
            "ident": _y("platform/identity.yaml"), "dl": _y("policies/data-leases.yaml"), "pol": _limits()}


def _limits(ctx: dict | None = None) -> dict:
    """Data limits from policy packs (ADR-0100), resolved for a context (tenant, trust, band)."""
    from data_policy import limits
    return limits(ctx)


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str).encode()


def digest(env: dict) -> str:
    """Over the whole envelope except the digest itself; input digests make the chain a Merkle DAG."""
    return "sha256:" + hashlib.sha256(_canon({k: v for k, v in env.items() if k != "digest"})).hexdigest()


def _sign(step: dict, key) -> dict:
    if key is not None:
        step["signature"] = key.sign(_canon({k: v for k, v in step.items() if k != "signature"})).hex()
    return step


def source_envelope(d: dict, product: str, as_of: str = "2026-10-10", keys: dict | None = None,
                    unidentified: int = 0, subject: dict | None = None, measurements: dict | None = None) -> dict:
    """An originating unit. `unidentified` counts sources its author relied on but did not identify (a claim in a
    chat message); `subject` identifies the unit without content (message id and span selector with span digest, or a
    physical item and the digest of its photographed surrogate)."""
    p = d["dp"]["products"][product]
    keys, measurements = keys or {}, measurements or {}
    level = p["assurance"]
    if level == "attested" and not all(measurements.get(o) for o in p["originators"]):
        level = "signed"     # attested needs a measurement (TPM quote digest) per originator, else it is only signed
    if level == "transcribed" and not all((subject or {}).get(k) for k in ("physical_item", "surrogate_digest", "capture_signer")):
        raise ValueError(f"{product}: a transcribed unit names its physical item, surrogate digest and capture signer")
    env = {"product": product, "sources": [product], "recorded": as_of, "label": p["label"],
           "assurance": "unidentified" if unidentified else level, "complete": not unidentified,
           "unidentified": unidentified, "subject": subject, "authored": bool(p.get("authored")), "fidelity": None,
           "releasable_to": p["releasable_to"], "purposes": sorted(p["purposes"]),
           "valid_until": (date.fromisoformat(as_of) + timedelta(days=p["retention_days"])).isoformat(),
           "originators": sorted(p["originators"]), "uplifted_by": None,
           "chain": [_sign({"actor": o, "activity": "originate", "inputs": [], "read_set": [],
                            "params": {"measurement": measurements.get(o)} if measurements.get(o) else {},
                            "at": as_of, "on_behalf_of": None}, keys.get(o)) for o in sorted(p["originators"])]}
    env["digest"] = digest(env)
    return env


def derive(d: dict, inputs: list[dict], actor: str, activity: str, aggregate: bool = False, persons: int = 0,
           group_size: int | None = None, read_set: list[str] | None = None, at: str = "2026-10-10",
           on_behalf_of: str | None = None, key=None, run: dict | None = None,
           selectors: dict | None = None, tenant: str | None = None, minimisation: dict | None = None,
           interpretation: dict | None = None) -> dict:
    """Never wider than the narrowest input, never lower than the highest input. The envelope holds only its own
    step; history lives in the store, reached through input digests (constant size at any depth). A pipeline run
    in one trust domain may be one step with run={internal_steps, log_root} (ADR-0097)."""
    prop = d["pv"]["propagation"]
    order = d["pv"]["rings"]["order"]
    declared = [i["digest"] for i in inputs]
    reads = sorted(read_set) if read_set is not None else sorted(declared)
    undeclared = set(reads) - set(declared)
    if undeclared:
        raise ValueError(f"undeclared input read by {actor}: {sorted(undeclared)} (fail closed)")
    label = max((i["label"] for i in inputs), key=LABELS.index)
    floor = (_limits({"tenant": tenant}) if tenant else d["pol"])["min_group_size"]
    if aggregate and label != "Internal" and (group_size or 0) < floor:
        raise ValueError(f"aggregate of {label} data below the minimum group size {floor}")
    uplifted_by = next((i["uplifted_by"] for i in inputs if i.get("uplifted_by")), None)
    selectors = selectors or {}
    if set(selectors) - set(declared):
        raise ValueError("a selector points at an input the step does not declare")
    for sel in selectors.values():
        if not (isinstance(sel.get("start"), int) and isinstance(sel.get("end"), int) and sel["start"] < sel["end"]
                and sel.get("keyed_digest") and sel.get("unit")):
            raise ValueError("a selector needs the unit's version, start < end and a keyed span digest")
    # ADR-0104: an authored unit (a message, a room post) is written under the purpose of what it cites, so authored
    # inputs never narrow the purposes when cited data is present; they still bring author, label and assurance
    cited = [i for i in inputs if not i.get("authored")]
    purpose_inputs = cited or inputs
    mixed = len({frozenset(i["purposes"]) for i in purpose_inputs}) > 1
    ends = min(i["valid_until"] for i in inputs)
    if minimisation:
        mz = d["pv"]["minimisation"]
        if minimisation.get("kind") not in mz["kinds"]:
            raise ValueError(f"minimisation kind {minimisation.get('kind')} is not registered")
        cap = d["dp"]["mesh"]["global_policy"]["max_retention_days"][label]
        if not 0 < int(minimisation.get("retain_days", 0)) <= cap:
            raise ValueError(f"a minimised {label} unit is kept at most {cap} days")
        ends = (date.fromisoformat(str(at)[:10]) + timedelta(days=int(minimisation["retain_days"]))).isoformat()
    assurance = max((i["assurance"] for i in inputs), key=ASSURANCE.index)
    fids = [i["fidelity"] for i in inputs if i.get("fidelity")]
    if interpretation:
        if not 0 <= float(interpretation.get("confidence", -1)) <= 1 or not interpretation.get("method"):
            raise ValueError("a machine interpretation names its method and a confidence between 0 and 1")
        assurance = max(assurance, d["pv"]["interpretation"]["assurance_at_best"], key=ASSURANCE.index)
        fids.append(interpretation)
    fidelity = min(fids, key=lambda f: float(f["confidence"])) if fids else None
    if aggregate and (mixed or persons > 1000) and not uplifted_by:
        label = LABELS[min(LABELS.index(label) + 1, len(LABELS) - 1)]
        uplifted_by = actor
    step = _sign({"actor": actor, "activity": activity, "inputs": declared, "read_set": reads,
                  "params": {"aggregate": aggregate, "persons": persons, "group_size": group_size, "run": run,
                             "selectors": selectors, "tenant": tenant, "minimisation": minimisation,
                             "interpretation": interpretation},
                  "at": at, "on_behalf_of": on_behalf_of}, key)
    env = {"label": label,
           "releasable_to": min((i["releasable_to"] for i in inputs), key=order.index),
           "purposes": sorted(set.intersection(*(set(i["purposes"]) for i in purpose_inputs))),
           "valid_until": ends,
           "originators": sorted(set().union(*(i["originators"] for i in inputs))),
           "sources": sorted(set().union(*(i["sources"] for i in inputs))),
           "uplifted_by": uplifted_by,
           "assurance": assurance,
           "complete": all(i["complete"] for i in inputs),
           "authored": False, "fidelity": fidelity,
           "chain": [step]}
    env["digest"] = digest(env)
    return env


POLICY_FIELDS = {"label", "ring", "owner", "purpose", "trust_domain"}


def _verify_one(d: dict, env: dict, known: dict[str, dict], keys: dict | None, runs: dict | None) -> list[str]:
    from provenance_log import key_valid, mth, public_key
    if digest(env) != env.get("digest"):
        return ["digest does not match the envelope (altered after signing)"]
    last = env["chain"][-1]
    if last["activity"] == "originate":
        try:
            ref = source_envelope(d, env["product"], env["recorded"], unidentified=env.get("unidentified", 0),
                                  subject=env.get("subject"),
                                  measurements={s["actor"]: s["params"].get("measurement") for s in env["chain"]})
        except ValueError as e:
            return [str(e)]
    else:
        run = (last.get("params") or {}).get("run")
        if run:
            steps = (runs or {}).get(run.get("log_root"))
            if steps is None:
                return [f"run by {last['actor']}: run log {str(run.get('log_root'))[:12]} missing"]
            if mth([_canon(x) for x in steps]).hex() != run["log_root"] or len(steps) != run.get("internal_steps"):
                return [f"run by {last['actor']}: run log does not match its root or step count"]
            folded = [x for x in steps if POLICY_FIELDS & set(x.get("changes", []))]
            if folded:
                return [f"run by {last['actor']}: {len(folded)} internal step(s) change label, ring, owner, purpose or trust domain; they must be their own steps"]
        try:
            ref = derive(d, [known[i] for i in last["inputs"]], last["actor"], last["activity"],
                         read_set=last["read_set"], at=last["at"], on_behalf_of=last["on_behalf_of"], **last["params"])
        except ValueError as e:
            return [str(e)]
    errs = [f"{f} differs from what the inputs give" for f in DERIVED_FIELDS if ref.get(f) != env.get(f)]
    if keys is not None:
        from cryptography.exceptions import InvalidSignature
        for st in env["chain"]:
            entry, sig = keys.get(st["actor"]), st.get("signature")
            if not entry or not sig:
                errs.append(f"step by {st['actor']}: unsigned or unknown key")
                continue
            if not key_valid(entry, st["at"]):
                errs.append(f"step by {st['actor']}: key not valid at {st['at']}")
                continue
            if st["activity"] == "originate" and env.get("assurance") == "attested" and not (
                    isinstance(entry, dict) and entry.get("attested")):
                errs.append(f"step by {st['actor']}: claims attested but the key register does not mark it attested")
                continue
            try:
                public_key(entry).verify(bytes.fromhex(sig), _canon({k: v for k, v in st.items() if k != "signature"}))
            except InvalidSignature:
                errs.append(f"step by {st['actor']}: bad signature")
    return errs


def verify(d: dict, env: dict, known: dict[str, dict], keys: dict | None = None, checkpoints: list | None = None,
           checkpoint_signers: dict | None = None, revoked: set | frozenset = frozenset(),
           runs: dict | None = None) -> list[str]:
    """Verify an envelope and everything it rests on, iteratively (any depth), inputs before dependents.

    keys: actor -> public key, or {key, not_before, not_after, revoked_at}. A step is checked against the key valid
    at its time, so identities that have since died (spun-down ephemeral PoPs) still verify. Production verifiers
    always pass the replicated key register.
    checkpoints: signed statements from registered verifiers; a vouched digest is not walked again, but its own
    digest is still recomputed. A revoked checkpoint forces the full walk.
    runs: run-log root -> internal steps, for steps that fold a pipeline run (ADR-0097)."""
    from provenance_log import trusted_digests
    trusted = trusted_digests(checkpoints or [], checkpoint_signers or {}, revoked)
    if digest(env) != env.get("digest"):
        return ["digest does not match the envelope (altered after signing)"]
    order: list[dict] = []
    seen: set[str] = set()
    stack: list[tuple[dict, bool]] = [(env, False)]
    errs: list[str] = []
    while stack:
        e, done = stack.pop()
        if done:
            order.append(e)
            continue
        if e["digest"] in seen:
            continue
        seen.add(e["digest"])
        stack.append((e, True))
        if e["digest"] in trusted:
            continue
        last = e["chain"][-1]
        for i in ([] if last["activity"] == "originate" else last["inputs"]):
            if i not in known:
                errs.append(f"input {i[:19]} unknown: cannot verify (unverifiable lineage, fail closed)")
            elif i not in seen:
                stack.append((known[i], False))
    if errs:
        return errs
    for e in order:
        if e["digest"] in trusted:
            if digest(e) != e["digest"]:
                return ["a checkpointed envelope does not match its digest"]
            entry = (checkpoint_signers or {}).get(trusted[e["digest"]])
            scope = entry.get("scope") if isinstance(entry, dict) else None
            if scope:
                prods = scope.get("products", "*")
                if prods != "*" and not set(e["sources"]) <= set(prods):
                    return [f"checkpoint by {trusted[e['digest']]} vouches outside its scope (sources {e['sources']})"]
                if LABELS.index(e["label"]) > LABELS.index(scope.get("max_label", "Restricted")):
                    return [f"checkpoint by {trusted[e['digest']]} vouches above its label scope"]
            continue
        errs += _verify_one(d, e, known, keys, runs)
        if errs:
            return errs
    return errs


def source_request(d: dict, env: dict) -> list[dict]:
    """For a unit whose author relied on unidentified sources: who is asked to name them (ADR-0099)."""
    if env.get("complete", True):
        return []
    st = stewards(d)
    return [{"to": resolve(d, o, st.get(env["product"]))[0], "about": env["digest"], "ask": "identify the source(s) this relied on",
             "sla_hours": d["pv"]["assurance"]["source_request_sla_hours"]} for o in env["originators"]]


def fail_closed(d: dict, env: dict) -> dict:
    """What an envelope may do while its lineage cannot be verified (inputs lost, e.g. a PoP that died undrained):
    Restricted, no wider than the site, until a steward decides (ADR-0097 ddil)."""
    order = d["pv"]["rings"]["order"]
    ring = min(env["releasable_to"], "site", key=order.index)
    return dict(env, label="Restricted", releasable_to=ring, state="unverifiable")


class Store:
    """The lineage store, anchored to the transparency log: an envelope enters only with its log entry, a valid
    digest and its inputs present (ADR-0097). The store is untrusted; the log is the anchor."""

    def __init__(self, log):
        self.log = log
        self.by_digest: dict[str, dict] = {}
        self.children: dict[str, set[str]] = {}

    def put(self, env: dict, index: int) -> str:
        dg = env["digest"]
        if digest(env) != dg:
            raise ValueError("envelope does not match its digest")
        if index >= len(self.log.leaves) or self.log.leaves[index] != dg.encode():
            raise ValueError(f"{dg[:19]} is not at log index {index}")
        last = env["chain"][-1]
        missing = [i for i in ([] if last["activity"] == "originate" else last["inputs"]) if i not in self.by_digest]
        if missing:
            raise ValueError(f"{dg[:19]}: inputs not in the store {[m[:19] for m in missing]}")
        self.by_digest[dg] = env
        for i in ([] if last["activity"] == "originate" else last["inputs"]):
            self.children.setdefault(i, set()).add(dg)
        return dg

    def history(self, dg: str, stop: set | frozenset = frozenset()) -> list[dict]:
        """Every step this envelope rests on, each once, dependents before their inputs; `stop` is a cut set."""
        post, seen = [], set()
        stack: list[tuple[str, bool]] = [(dg, False)]
        while stack:
            cur, done = stack.pop()
            if done:
                post.append(cur)
                continue
            if cur in seen or cur not in self.by_digest:
                continue
            seen.add(cur)
            e = self.by_digest[cur]
            if digest(e) != cur:
                raise ValueError(f"store returned an altered envelope for {cur[:19]}")
            stack.append((cur, True))
            last = e["chain"][-1]
            if cur not in stop and last["activity"] != "originate":
                stack += [(i, False) for i in last["inputs"]]
        return [s for x in reversed(post) for s in self.by_digest[x]["chain"]]


def resolve(d: dict, principal: str, steward: str | None = None) -> tuple[str, list[str]]:
    """Follow acts_for to a living person-role or board; else the steward, then the governance board."""
    reg, path = d["dp"]["principals"], []
    cur = principal
    while cur in reg:
        if cur in path:
            raise ValueError(f"acts_for cycle at {cur}")
        path.append(cur)
        p = reg[cur]
        if p["kind"] in LIVING:
            if p.get("status") == "active":
                return cur, path
            break
        cur = p.get("acts_for")
    for fb in (steward, "data-governance-board"):
        if fb and reg.get(fb, {}).get("kind") in LIVING and reg[fb].get("status") == "active":
            return fb, path + [fb]
    raise ValueError(f"no living authority for {principal}")


def stewards(d: dict) -> dict[str, str]:
    return {p: dom["owner"] for dom in d["dp"]["mesh"]["domains"].values() for p in dom["products"]}


def authority(d: dict, product: str, today: str) -> str:
    """The product's deciding principal: its owner while the ownership lease runs, else its steward."""
    p, st = d["dp"]["products"][product], stewards(d).get(product)
    if p.get("owner_until") and str(p["owner_until"]) < today:
        return resolve(d, st or "data-governance-board")[0]
    return resolve(d, p["owner"], st)[0]


def reader_ring(d: dict, data_site: str, reader: dict, now) -> str:
    """The ring a reader is in relative to the data's site (ADR-0107): inside the site only on an attested, enrolled,
    managed device on that site's overlay with no other route; otherwise the tenant for the tenant's own people, else
    federation. Facts decide, not where an account lives. A bare `site` claim is not evidence of being there, and `now`
    is required (no frozen default clock): ADR-0126."""
    from clock import future, utc
    dev = reader.get("device") or {}
    lease = d["pv"]["rings"]["inside_site"]["devices"]["attestation_lease_minutes"]
    attested = dev.get("attested_at")
    try:
        fresh = bool(attested) and not future(attested, now) and (utc(now) - utc(attested)).total_seconds() <= lease * 60
    except (TypeError, ValueError):
        fresh = False
    if (fresh and dev.get("enrolled") == "active" and dev.get("overlay_site") == data_site and dev.get("overlay_only")
            and dev.get("managed")):
        return "site"
    return "tenant" if reader.get("tenant_member") else "federation"


def current_lease(d: dict, product: str, reader: str, purpose: str, today: str) -> str | None:
    """The id of an active lease on the product for this purpose held by the reader (a person-role or a consumer)."""
    for l in d["dp"].get("leases", []):
        if (l["product"] == product and l["consumer"] == reader and l["purpose"] == purpose
                and l.get("status") == "active" and str(l["from"]) <= today <= str(l["until"])):
            return l["id"]
    return None


def route(d: dict, env: dict, request: dict, today: str = "2026-10-10") -> dict:
    """Who must approve an access or release request on this envelope, or why it is refused."""
    rings, req = d["pv"]["rings"], d["pv"]["requests"]
    order = rings["order"]
    target, purpose, kind = request["target_ring"], request["purpose"], request["kind"]
    # a band the request does not carry, or does not name correctly, is the strictest one: dropping a field never
    # loosens. The requester's and the site's band are always needed; the principal's band
    # whenever the request is made on someone's behalf.
    need = ("band", "site_band") + (("on_behalf_band",) if request.get("on_behalf_of") else ())
    given = [request.get(k) for k in need] + [request[k] for k in ("on_behalf_band",) if k not in need and request.get(k)]
    band = max((b if b in BANDS else BANDS[-1] for b in given), key=BANDS.index)
    band = max(band, env.get("band", "green"), key=BANDS.index)
    if order.index(target) > order.index(rings["band_cap"][band]):
        return {"decision": "refused", "reason": f"effective band {band} caps ring crossings at {rings['band_cap'][band]}"}
    ctx = {"trust": request.get("trust", "none"), "band": band} | ({"tenant": request["tenant"]} if request.get("tenant") else {})
    lim = _limits(ctx)
    for prod in env["sources"]:   # ADR-0104: the ceiling no declassification lifts
        ceiling = lim["ring_ceiling"][d["dp"]["products"][prod]["label"]]
        if order.index(target) > order.index(ceiling):
            return {"decision": "refused", "reason": f"{d['dp']['products'][prod]['label']} data from {prod} never leaves the {ceiling} ring"}
    cap = lim["max_ring_by_assurance"].get(env["assurance"])
    if cap and order.index(target) > order.index(cap):
        return {"decision": "refused", "reason": f"{env['assurance']} provenance stays within {cap} until its sources are named"}
    new_label = request.get("new_label")
    lowering = bool(new_label) and LABELS.index(new_label) < LABELS.index(env["label"])
    widening = order.index(target) > order.index(env["releasable_to"])
    if kind == "access" and (widening or lowering):
        return {"decision": "refused", "reason": "access stays inside the data's ring and label; ask with a release request"}
    effective_label = new_label if lowering else env["label"]
    beyond_label = order.index(target) > order.index(lim["label_max_ring"][effective_label])
    declassification = lowering or beyond_label
    try:
        approvers: list[str] = []
        reader, entitled = request.get("reader"), []
        for prod in env["sources"]:
            p = d["dp"]["products"][prod]
            # an authored source blocks only on its own ring and label; purpose and declassification of cited data
            # are decided by the cited data's owners (ADR-0104)
            blocks = (order.index(target) > order.index(p["releasable_to"])
                      or order.index(target) > order.index(lim["label_max_ring"][p["label"]])
                      or (not p.get("authored") and (purpose not in p["purposes"] or declassification)))
            if reader and not blocks and not p.get("authored"):   # ADR-0104: the reader must hold a current lease
                lease = current_lease(d, prod, reader, purpose, today)
                if lease:
                    entitled.append(lease)
                else:
                    blocks = True
            if blocks:
                approvers.append(authority(d, prod, today))
        if beyond_label and env.get("uplifted_by") and not lowering:
            approvers.append(resolve(d, env["uplifted_by"])[0])          # the uplift belongs to who aggregated
        extra = []
        if kind == "release" and order.index(target) >= order.index("tenant"):
            extra.append("release_officer")
        if env["label"] == "Restricted" and approvers:   # ADR-0104: the steward of the most sensitive source
            ranked = sorted(env["sources"], key=lambda x: -LABELS.index(d["dp"]["products"][x]["label"]))
            others = [s for s in (stewards(d).get(x) for x in ranked) if s and s not in approvers]
            extra.append(others[0] if others else "data-governance-board")
        if declassification or band != "green":
            extra.append("security_officer")
        weak = not env["complete"] or ASSURANCE.index(env["assurance"]) > ASSURANCE.index(d["pv"]["assurance"]["min_for_release"])
        if kind == "release" and weak and order.index(target) >= order.index("tenant"):
            authors = {resolve(d, o)[0] for o in env["originators"] if o in d["dp"]["principals"]}
            extra.append("provenance-reviewer" if "provenance-reviewer" not in authors else "data-governance-board")
        excluded = {request.get("requester"), request.get("on_behalf_of")} - {None}
        if excluded:
            excluded |= {resolve(d, x)[0] for x in list(excluded) if x in d["dp"]["principals"]}
        final: list[str] = []
        for a in approvers + extra:
            if a in excluded:   # nobody approves their own request: the steward or the board steps in
                a = next((s for s in (stewards(d).get(x) for x in env["sources"]) if s and s not in excluded),
                         "data-governance-board")
            if a not in final:
                final.append(a)
    except ValueError as e:
        return {"decision": "refused", "reason": f"no deciding authority: {e}"}
    out = {"effective_band": band, "declassification": declassification, "no_common_purpose": not env["purposes"],
           "entitled": entitled if reader else None,
           "assurance": env["assurance"], "provenance_complete": env["complete"],
           "sla_hours": req["sla_hours"][kind]}
    if not final:
        return out | {"decision": "allowed-by-policy", "approvers": []}
    return out | {"decision": "needs-approval", "approvers": final}


def view(d: dict, env: dict, ring: str) -> dict:
    """The envelope as shown in a ring: beyond the tenant, identities become per-envelope pseudonyms with their kind."""
    order = d["pv"]["rings"]["order"]
    if order.index(ring) <= order.index(d["pv"]["chain_privacy"]["full_up_to"]):
        return env
    reg = d["dp"]["principals"]

    def mask(a):
        if a is None:
            return None
        return f"{reg.get(a, {}).get('kind', 'unknown')}:" + hashlib.sha256((env["digest"] + a).encode()).hexdigest()[:12]
    v = copy.deepcopy(env)
    v["originators"] = sorted(mask(o) for o in env["originators"])
    v["chain"] = [dict(s, actor=mask(s["actor"]), on_behalf_of=mask(s["on_behalf_of"])) for s in env["chain"]]
    v["uplifted_by"] = mask(env.get("uplifted_by"))
    v["redacted"] = True
    return v


def merkle_root(members: list) -> str:
    """Batch or snapshot membership root (RFC 9162 tree shape, shared with the transparency log)."""
    from provenance_log import mth
    return mth([_canon(m) for m in members]).hex()


def prove(members: list, index: int) -> list[str]:
    from provenance_log import inclusion_proof
    return [h.hex() for h in inclusion_proof(index, [_canon(m) for m in members])]


def included(member, index: int, size: int, proof: list[str], root: str) -> bool:
    from provenance_log import verify_inclusion
    return verify_inclusion(index, size, _canon(member), [bytes.fromhex(h) for h in proof], bytes.fromhex(root))


def impact(d: dict, envelopes: list[dict], artefacts: list[dict], changed: str, kind: str, today: str) -> dict:
    """Walk the graph forward from a changed envelope digest: every dependent becomes stale or tainted (the worst
    input state wins, transitively); artefacts citing a dependent take its state, or become historical when their
    relevance has lapsed. Returns {digest or artefact id: state}."""
    ch = d["pv"]["change"]
    order = ch["states"]["order"]
    hit = ch["kinds"][kind]["downstream"]
    children: dict[str, list[str]] = {}
    for e in envelopes:
        for i in e["chain"][-1]["inputs"] if e["chain"] else []:
            children.setdefault(i, []).append(e["digest"])
    state: dict[str, str] = {}
    todo = [changed]
    while todo:
        cur = todo.pop()
        for c in children.get(cur, []):
            if order.index(hit) > order.index(state.get(c, "current")):
                state[c] = hit
                todo.append(c)
    out = dict(state)
    for a in artefacts:
        refs = [state.get(r, "current") if r != changed else hit for r in a["refs"]]
        worst = max(refs, key=order.index)
        if worst != "current":
            out[a["id"]] = "historical" if a.get("relevant_until") and str(a["relevant_until"]) < today else worst
    return out


def check(d: dict) -> list[str]:
    pv, dp = d["pv"], d["dp"]
    order, errs = pv["rings"]["order"], []
    reg, st = dp["principals"], stewards(d)
    for name, p in dp["products"].items():
        ring = p.get("releasable_to")
        if ring not in order:
            errs.append(f"product {name}: releasable_to must be one of {order}")
        elif order.index(ring) > order.index(d["pol"]["label_max_ring"][p["label"]]):
            errs.append(f"product {name}: releasable_to {ring} is wider than {p['label']} allows")
        if not p.get("originators"):
            errs.append(f"product {name}: no originating identities")
        for o in p.get("originators", []):
            if o not in reg:
                errs.append(f"product {name}: originator {o} is not a registered principal")
                continue
            try:
                resolve(d, o, st.get(name))
            except ValueError as e:
                errs.append(f"product {name}: {e}")
        if reg.get(p["owner"], {}).get("kind") not in LIVING:
            errs.append(f"product {name}: owner {p['owner']} must be a registered person-role or board")
        if reg.get(st.get(name), {}).get("kind") not in LIVING:
            errs.append(f"product {name}: steward {st.get(name)} must be a registered person-role or board")
    for l in dp.get("leases", []):
        c, p = dp.get("consumers", {}).get(l["consumer"]), dp["products"].get(l["product"])
        if c is None:
            errs.append(f"lease {l['id']}: consumer {l['consumer']} has no ring")
        elif p and order.index(c["ring"]) > order.index(p["releasable_to"]):
            errs.append(f"lease {l['id']}: consumer ring {c['ring']} is wider than {l['product']} may go ({p['releasable_to']})")
    for k, v in reg.items():
        if v["kind"] in pv["authority"]["attribution_only"] and not v.get("acts_for"):
            errs.append(f"principal {k}: a {v['kind']} must name whom it acts for")
        try:
            resolve(d, k)
        except ValueError as e:
            if "cycle" in str(e):
                errs.append(f"principal {k}: {e}")
    kinds = set(d["ident"]["subject_kinds"]) | {"sensor"}
    errs += [f"identity kind {k}: no acts_for rule" for k in sorted(kinds - set(pv["authority"]["acts_for"]))]
    caps = [order.index(pv["rings"]["band_cap"][b]) for b in BANDS]
    if caps != sorted(caps, reverse=True):
        errs.append("band_cap must narrow from green to black")
    if reg.get("data-governance-board", {}).get("status") != "active":
        errs.append("the data governance board must exist: it is the last fallback")
    have = {p.get("data_class", "business") for p in dp["products"].values()}
    errs += [f"data class {k}: no registered product (platform data is never exempt)" for k in pv["applies_to"]["data_classes"] if k not in have]
    for role, r in pv["oversight"]["roles"].items():
        if "content" in r["sees"] or "content" not in r["never"]:
            errs.append(f"oversight {role}: must never see content")
    inv = d["dl"]["lease_kinds"].get("investigation", {})
    if ("distinct persons" not in str(inv.get("granted_by", "")) or not inv.get("max_ttl")
            or not inv.get("max_records") or inv.get("max_renewals", 99) > 1 or not inv.get("report_to")):
        errs.append("oversight: content access needs a two-person (distinct roles), time-boxed, capped, reported investigation lease")
    for k in ("holds_per_pop", "key_register", "isolated_access", "nesting", "full_history"):
        if not pv.get("federation", {}).get(k):
            errs.append(f"federation: {k} must be declared")
    for k in ("offline_verification", "dead_identities", "site_logs", "drain_before_spin_down", "undrained"):
        if not pv.get("ddil", {}).get(k):
            errs.append(f"ddil: {k} must be declared")
    for name, p in dp["products"].items():
        if p.get("assurance") not in ASSURANCE[:-1]:
            errs.append(f"product {name}: assurance must be one of {ASSURANCE[:-1]} (unidentified is per unit, never per product)")
        if p.get("data_class") == "policy" and p.get("assurance") not in ("attested", "signed"):
            errs.append(f"product {name}: policy must be at least signed")
    for g, v in pv["identifiers"]["granules"].items():
        if not v.get("id") or v.get("unique_in") not in ("global", "tenant") or v.get("envelope") not in (
                True, False, "by-reference", "inclusion"):
            errs.append(f"granule {g}: needs an id scheme, a uniqueness scope and how it links to an envelope")
    return errs


if __name__ == "__main__":
    data = load()
    problems = check(data)
    print(f"products {len(data['dp']['products'])}, principals {len(data['dp']['principals'])}, rings {len(data['pv']['rings']['order'])}")
    for x in problems:
        print("ERROR", x)
    sys.exit(1 if problems else 0)
