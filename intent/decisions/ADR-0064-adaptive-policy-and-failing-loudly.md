# ADR-0064: Adaptive policy with risk bands, dynamic workload profiles and failing loudly

- Status: accepted
- Date: 2026-10-08
- Decider: maintainer

## Decision
platform/adaptive-policy.yaml and tools/adaptive.py turn fresh signals (role, persona status, device posture,
network, location, time of day, public IP reputation, site environment, world state, behaviour) into a risk band
(green, amber, red, black): hard rules first (suspended, under review, failed posture, blocked location, malicious
IP), then a weighted score; a missing or stale required signal adds risk, so unknown is never green. Each request path
names the worst band it tolerates; amber may require a CIBA step-up. Red denies everything except the status and help
service (NetBird quarantine group); black revokes credentials and the stick shows its state screen from the cached
revocation list.

A remote browser session is profiled dynamically: open (allow-listed egress only) or isolated (no internal and no
external traffic, quarantine label for Cilium) when its owner is red or black, its image is not attested, perimeters
drift, an egress incident is open, or the world state is severe.

Failing loudly: every refusal reaches the person on the stick state screen, a gateway interstitial page, RFC 9457
problem details for APIs, or the decision inbox's 'my access' view, with what happened, a reason code, what to do,
whom to contact, a reference and the time, in English, Dutch and French. Reasons that could tip off an investigation
(under review, suspended, malicious IP) are discreet by default: a neutral text is shown and the real reason goes to
the security officer, who can set disclosure per case.
