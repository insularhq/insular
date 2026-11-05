#!/bin/bash
# The resolver's trust anchor (ADR-0172 amendment): on the lab the apex's KSK is read from the Isle's Knot at
# start, a stand-in for the anchor a key ceremony distributes. Writes the anchor and the resolver's configuration
# (its NSID is the pod's name). Args: apex, the authoritative server's address.
set -u
APEX=$1; AUTH=$2; OUT=${ANCHOR_OUT:-/etc-out}; TPL=${ANCHOR_TEMPLATE:-/template}   # overridable for the model's test
keys=""
for i in $(seq 1 60); do
  keys=$(kdig @"$AUTH" +short +norec "$APEX" DNSKEY 2>/dev/null | awk '$1 == 257')
  [ -n "$keys" ] && break
  sleep 5
done
[ -n "$keys" ] || { echo "anchor: no KSK for $APEX from $AUTH after 5 minutes"; exit 1; }
echo "$keys" | sed "s/^/$APEX. 3600 IN DNSKEY /" > $OUT/apex.key
sed "s/__NSID__/$HOSTNAME/" $TPL/resolver.yaml > $OUT/config.yaml
echo "anchor: $(echo "$keys" | wc -l) KSK for $APEX from the Isle's Knot"
# A federation parent: set by the organisation's operation (the lab tooling) from the
# parent's letter, in the optional ConfigMap dns-federation-parent, never from git. Without it nothing changes.
P=${ANCHOR_PARENT:-/parent}
if [ -s $P/suffix ] && [ -s $P/address ] && [ -s $P/anchor ]; then
  SUF=$(tr -d ' \r\n' < $P/suffix); ADDR=$(tr -d ' \r\n' < $P/address)
  case "$SUF" in ""|*[!a-z0-9.-]*) echo "anchor: parent suffix '$SUF' refused (lower-case letters, digits, dots, hyphens)"; exit 1 ;; esac
  case "$ADDR" in ""|*[!0-9a-fA-F.:,]*) echo "anchor: parent address refused (IP addresses, comma-separated)"; exit 1 ;; esac
  # only DNSKEY records of the suffix itself are accepted as its anchor
  grep -E "^${SUF//./\\.}\.? +([0-9]+ +)?(IN +)?DNSKEY +257 +3 +[0-9]+ +[A-Za-z0-9+/= ]+$" $P/anchor > $OUT/parent.key
  [ -s $OUT/parent.key ] || { echo "anchor: no DNSKEY 257 record for $SUF in the parent's anchor"; exit 1; }
  servers=$(echo "$ADDR" | tr ',' '\n' | sed "s/.*/'&'/" | paste -sd, -)
  awk -v suf="$SUF" -v srv="$servers" '
    /^# __PARENT_ANCHOR__$/ { print "    - file: /etc/knot-resolver/parent.key"; print "      read-only: true"; next }
    /^# __PARENT_FORWARD__$/ { print "  - subtree: " suf; print "    servers: [" srv "]"; print "    options: {authoritative: true, dnssec: true}"; next }
    { print }' $OUT/config.yaml > $OUT/config.tmp && mv $OUT/config.tmp $OUT/config.yaml
  echo "anchor: parent $SUF at $ADDR, $(wc -l < $OUT/parent.key) KSK from the organisation's letter"
fi
