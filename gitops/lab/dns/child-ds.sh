#!/bin/bash
# The Isle's DS in the apex (ADR-0172 amendment). On the lab the apex stands in for the Chartroom's, so this
# helper beside the signer places the child's current DS (SHA-256 of its KSK) there through the control socket. A
# reload of the apex's zone file drops records the file does not carry; the next pass puts the DS back.
# Prints key tags only. Args: apex, the child's label.
set -u
C=/config/knot.conf; S=/rundir/knot.sock; APEX=$1; LABEL=$2; CHILD=$LABEL.$APEX
ds() { sed -n 's/.* DS \([0-9]* 13 2 [0-9A-Fa-f]*\).*/\1/p' | sort; }
until knotc -s $S zone-status $CHILD >/dev/null 2>&1 && knotc -s $S zone-status $APEX >/dev/null 2>&1; do sleep 5; done
while true; do
  want=$(keymgr -c $C $CHILD ds 2>/dev/null | ds)
  have=$(knotc -s $S zone-read $APEX $LABEL DS 2>/dev/null | ds)
  if [ -n "$want" ] && [ "$want" != "$have" ]; then
    knotc -s $S zone-begin $APEX >/dev/null
    knotc -s $S zone-unset $APEX $LABEL DS >/dev/null 2>&1
    echo "$want" | while read -r d; do knotc -s $S zone-set $APEX $LABEL 3600 DS $d >/dev/null; done
    if knotc -s $S zone-commit $APEX >/dev/null; then
      echo "child DS in $APEX: key tags $(echo "$want" | awk '{print $1}' | tr '\n' ' ')"
    else
      knotc -s $S zone-abort $APEX >/dev/null 2>&1
      echo "child DS: commit refused"
    fi
  fi
  sleep 60
done
