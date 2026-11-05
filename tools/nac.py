"""802.1X on the boot stick: offer the pseudonymous EAP-TLS certificate only to a verified enterprise authenticator.

The stick answers EAP only when the network asks for it (wired EAPOL request or an enterprise SSID in a signed tenant
profile), and only after the RADIUS server's certificate chains to the pinned tenant CA and matches the expected
server name. Anything else gets no certificate: the stick falls back to the open path (captive portal, then VPN).
"""

from __future__ import annotations


def offer(observed: dict, profiles: dict, home_unlocked: bool) -> tuple[bool, list[str]]:
    """Whether to present the 802.1X certificate on this network. Every reason is returned; deny overrides."""
    why = []
    if not home_unlocked:
        why.append("the certificate's key is in the encrypted home: sign in first")
    if not observed.get("eap_requested"):
        why.append("the network did not ask for 802.1X")
    prof = profiles.get(observed.get("network_id"))
    if prof is None:
        why.append("no signed tenant profile for this network")
    else:
        if observed.get("server_ca") != prof["radius_ca_pin"]:
            why.append("RADIUS server certificate does not chain to the pinned tenant CA")
        if observed.get("server_name") != prof["server_name"]:
            why.append("RADIUS server name does not match the profile")
        if observed.get("tls_version", "1.2") < prof.get("min_tls", "1.2"):
            why.append("TLS version below the profile minimum")
    return not why, why
