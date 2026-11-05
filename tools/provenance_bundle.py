"""Proof bundles: provenance across federation, nesting and isolation (ADR-0098).

A PoP never needs the lineage store of the whole estate. Data travels with a proof bundle containing:
- the envelope;
- its ancestors back to the nearest checkpoint signed by a verifier the receiver trusts;
- an inclusion proof for each of those envelopes in a transparency log;
- that log's signed tree head.

With the replicated key register (actor keys, checkpoint signers, log keys), the receiver verifies everything offline,
however long it has been cut off and whether or not the producing PoP still exists. Nesting stays cheap because each
boundary crossing re-checkpoints: a site verifies a PoP's bundle and vouches for it, so the bundle it forwards to its
parent or a peer is one envelope long. This is the Sigstore bundle idea, and simplified payment verification:
headers and Merkle proofs instead of the whole chain.

Usage (library): make_bundle, verify_bundle, rebundle.
"""
from __future__ import annotations

from data_provenance import digest, verify
from provenance_log import trusted_digests, verify_inclusion, verify_sth


def make_bundle(store, root: str, checkpoints: list[dict], log, sth: dict, ring: str = "tenant") -> dict:
    """The proof closure of `root`: ancestors up to (and including) checkpointed envelopes, with log proofs.
    Bundles carry full lineage, so they travel within the tenant only; beyond it a unit leaves through the release
    gateway as a released unit."""
    if ring not in ("host", "site", "tenant"):
        raise ValueError("proof bundles stay within the tenant: lineage is not redacted inside them")
    stop = {c["digest"] for c in checkpoints}
    envs: dict[str, dict] = {}
    todo = [root]
    while todo:
        cur = todo.pop()
        if cur in envs:
            continue
        e = store.by_digest[cur]
        envs[cur] = e
        last = e["chain"][-1]
        if cur not in stop and last["activity"] != "originate":
            todo += last["inputs"]
    index = {leaf.decode(): i for i, leaf in enumerate(log.leaves[: sth["size"]])}
    proofs = {}
    for dg in envs:
        if dg not in index:
            raise ValueError(f"{dg[:19]} is not in the log under this tree head: log it before bundling")
        proofs[dg] = {"index": index[dg], "path": [h.hex() for h in log.inclusion(index[dg], sth["size"])]}
    return {"root": root, "envelopes": list(envs.values()), "checkpoints": [c for c in checkpoints if c["digest"] in envs],
            "sth": sth, "proofs": proofs}


def verify_bundle(d: dict, b: dict, keys: dict, checkpoint_signers: dict, log_keys: dict,
                  revoked: set | frozenset = frozenset(), tombstones: set | frozenset = frozenset(),
                  now: str | None = None, register_issued: str | None = None, last_seen: dict | None = None) -> list[str]:
    """Offline verification: tree head signature, freshness and consistency with the last head seen, log inclusion of
    every envelope, then the envelope DAG down to trusted, in-scope, unrevoked checkpoints with step signatures
    checked against keys valid at each step's time. Tombstones (superseded or tainted units) and expired units fail."""
    from clock import future, utc
    from provenance_log import verify_consistency
    fed = d["pv"]["federation"]
    hours = lambda a, b_: (utc(a) - utc(b_)).total_seconds() / 3600
    sth = b["sth"]
    pub = log_keys.get(sth.get("log"))
    if not pub or not verify_sth(sth, pub):
        return [f"tree head of log {sth.get('log')} is not signed by a registered log key"]
    try:   # a malformed timestamp fails closed instead of raising; times are UTC, naive counts as UTC
        if now and register_issued and future(register_issued, now):
            return ["the key register is dated in the future: refuse it (fail closed)"]
        if now and register_issued and hours(now, register_issued) > fed["register_max_age_hours"]:
            return ["the key register is older than allowed: refresh it before trusting bundles (fail closed)"]
        if now and future(sth["ts"], now):
            return [f"tree head of log {sth['log']} is dated in the future: refuse it (fail closed)"]
        if now and hours(now, sth["ts"]) > fed["sth_max_age_hours"]:
            return [f"tree head of log {sth['log']} is stale (older than {fed['sth_max_age_hours']} h)"]
        if now and last_seen and last_seen.get("ts") and future(last_seen["ts"], now):
            return ["the clock is behind the last tree head seen: possible rollback (fail closed)"]
    except (TypeError, ValueError):
        return ["a timestamp in the bundle or the request cannot be read: fail closed"]
    if last_seen and last_seen.get("log") == sth.get("log"):
        if sth["size"] < last_seen["size"]:
            return ["tree head is older than one already seen: possible split view"]
        cons = b.get("consistency_from", {}).get(str(last_seen["size"]))
        if sth["size"] > last_seen["size"] and (cons is None or not verify_consistency(
                last_seen["size"], sth["size"], bytes.fromhex(last_seen["root"]), bytes.fromhex(sth["root"]),
                [bytes.fromhex(h) for h in cons])):
            return ["no valid consistency proof from the last tree head seen: possible split view"]
    if len(b["envelopes"]) > 2 * fed["checkpoint_every_steps"]:
        return ["bundle larger than twice the checkpoint interval: refused"]
    root_hash = bytes.fromhex(sth["root"])
    known = {}
    for e in b["envelopes"]:
        if digest(e) != e["digest"]:
            return ["an envelope in the bundle does not match its digest"]
        p = b["proofs"].get(e["digest"])
        if not p or not verify_inclusion(p["index"], sth["size"], e["digest"].encode(),
                                         [bytes.fromhex(h) for h in p["path"]], root_hash):
            return [f"{e['digest'][:19]} is not proven to be in log {sth['log']}"]
        known[e["digest"]] = e
    if b["root"] not in known:
        return ["the bundle does not contain its root envelope"]
    dead = [dg for dg in known if dg in tombstones]
    if dead:
        return [f"{dead[0][:19]} is superseded or tainted (tombstone): do not use"]
    # a vouching checkpoint carries the lineage its signer verified: later tombstones and revocations reach it
    from provenance_log import trusted_digests as _valid
    valid = _valid(b.get("checkpoints", []), checkpoint_signers)
    for c in b.get("checkpoints", []):
        if c.get("digest") in valid:
            line = set(c.get("lineage", []))
            if line & set(tombstones):
                return [f"an ancestor vouched for by {c['verifier']} is superseded or tainted (tombstone): do not use"]
            if line & set(revoked):
                return [f"{c['verifier']} vouched on an upstream checkpoint that is now revoked: do not use"]
    if now and known[b["root"]].get("valid_until") and str(known[b["root"]]["valid_until"]) < now[:10]:
        return ["the unit is past its valid_until"]
    return verify(d, known[b["root"]], known, keys, checkpoints=b["checkpoints"], checkpoint_signers=checkpoint_signers,
                  revoked=revoked)


def rebundle(d: dict, b: dict, keys: dict, checkpoint_signers: dict, log_keys: dict, verifier_key, verifier: str,
             log, sth_key, ts: str, *, revoked: set | frozenset, tombstones: set | frozenset, now: str,
             register_issued: str | None = None, last_seen: dict | None = None) -> dict:
    """A site (or parent) verifies an incoming bundle, logs the root in its own log, vouches for it with its own
    checkpoint and forwards a one-envelope bundle: nesting never accumulates envelopes. The site verifies with the
    same revocations, tombstones and clock as any receiver, and its
    checkpoint signs the lineage it verified, so what is revoked or tainted later still reaches the forwarded copy."""
    from provenance_log import checkpoint, trusted_digests
    if not now:
        raise ValueError("cannot vouch without a clock: freshness is part of the verification")
    errs = verify_bundle(d, b, keys, checkpoint_signers, log_keys, revoked=revoked, tombstones=tombstones, now=now,
                         register_issued=register_issued, last_seen=last_seen)
    if errs:
        raise ValueError(f"cannot vouch for an unverified bundle: {errs[0]}")
    valid = trusted_digests(b.get("checkpoints", []), checkpoint_signers)
    lineage = {e["digest"] for e in b["envelopes"]}
    for c in b.get("checkpoints", []):
        if c.get("digest") in valid:
            lineage |= {c["digest"]} | set(c.get("lineage", []))
    root = next(e for e in b["envelopes"] if e["digest"] == b["root"])
    idx = log.append(root["digest"])
    sth = log.sth(sth_key, ts)
    cp = checkpoint(verifier_key, verifier, root["digest"], sth["size"], lineage=sorted(lineage))
    return {"root": root["digest"], "envelopes": [root], "checkpoints": [cp], "sth": sth,
            "proofs": {root["digest"]: {"index": idx, "path": [h.hex() for h in log.inclusion(idx, sth["size"])]}}}


def trusted(b: dict, signers: dict) -> set[str]:
    return trusted_digests(b["checkpoints"], signers)
