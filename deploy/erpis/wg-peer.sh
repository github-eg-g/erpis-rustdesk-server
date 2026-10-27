#!/bin/bash
# Usage: wg-peer.sh add <name> <public-key> <ip>   e.g. add erpis-tech-01 <key> 10.97.0.2
#        wg-peer.sh remove <public-key>
#        wg-peer.sh list
# Peers are technicians; their private keys never leave their own devices.
set -euo pipefail
CONF=/etc/wireguard/wg0.conf
case "${1:-}" in
  add)
    NAME="$2"; PUB="$3"; IP="$4"
    echo "$PUB" | grep -Eq '^[A-Za-z0-9+/]{43}=$' || { echo "bad public key"; exit 1; }
    echo "$IP" | grep -Eq '^10\.97\.0\.([2-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-4])$' || { echo "ip must be 10.97.0.2-254"; exit 1; }
    grep -qF "$PUB" "$CONF" && { echo "key already present"; exit 1; }
    grep -qF "AllowedIPs = $IP/32" "$CONF" && { echo "ip already used"; exit 1; }
    printf '\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n' "$NAME" "$PUB" "$IP" >> "$CONF"
    ;;
  remove)
    PUB="$2"
    grep -qF "PublicKey = $PUB" "$CONF" || { echo "key not found"; exit 1; }
    awk -v k="PublicKey = $PUB" '
      BEGIN{RS="";ORS="\n\n"} index($0,k)==0 {print}' "$CONF" > "$CONF.new"
    mv "$CONF.new" "$CONF"; chmod 600 "$CONF"
    ;;
  list) ;;
  *) echo "usage: $0 add|remove|list"; exit 1;;
esac
wg syncconf wg0 <(wg-quick strip wg0)
wg show wg0
