#!/bin/sh
# One-time WireGuard server setup for technicians: 10.97.0.1/24 on UDP 51820.
# Split tunnel: no forwarding, no NAT; peers reach only this host.
set -eu
command -v wg >/dev/null || { apt-get update -q && apt-get install -y -q wireguard-tools; }
umask 077
mkdir -p /etc/wireguard
if [ ! -f /etc/wireguard/wg0.conf ]; then
  KEY=$(wg genkey)
  printf '[Interface]\nAddress = 10.97.0.1/24\nListenPort = 51820\nPrivateKey = %s\n' "$KEY" > /etc/wireguard/wg0.conf
fi
systemctl enable --now wg-quick@wg0
echo "server public key: $(wg show wg0 public-key)"
