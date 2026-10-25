#!/usr/bin/env bash
set -euo pipefail

# Run on the host, before NemoClaw onboarding. Never copy local-secrets to Git.
# The first IP is the certificate CN; every IP goes into the SAN list. The sandbox
# reaches the host via the openshell-docker bridge (172.18.0.1 here), so list it first.
if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <private MCP IP address> [more IPs...]" >&2
  exit 2
fi
for ip in "$@"; do
  if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    echo "Expected an IPv4 address: $ip" >&2
    exit 2
  fi
  IFS=. read -r a b c d <<< "$ip"
  for octet in "$a" "$b" "$c" "$d"; do
    if (( 10#$octet > 255 )); then
      echo "Invalid IPv4 address: $ip" >&2
      exit 2
    fi
  done
done
ip="$1"
san="$(printf 'IP:%s,' "$@")"
san="${san%,}"

umask 077
directory="$(cd "$(dirname "$0")" && pwd)/local-secrets"
if [[ -e "$directory/ca.key" || -e "$directory/mcp.key" ]]; then
  echo "Refusing to overwrite an existing CA or server key" >&2
  exit 1
fi
mkdir -m 700 -p "$directory"
chmod 700 "$directory"
extension_file="$(mktemp)"
trap 'rm -f "$extension_file"' EXIT
cat > "$extension_file" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=$san
EOF

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$directory/ca.key"
openssl req -x509 -new -sha256 -days 365 -key "$directory/ca.key" \
  -subj "/CN=ICE Local Development CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$directory/ca.crt"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$directory/mcp.key"
openssl req -new -sha256 -key "$directory/mcp.key" \
  -subj "/CN=$ip" -out "$directory/mcp.csr"
openssl x509 -req -sha256 -days 30 -in "$directory/mcp.csr" \
  -CA "$directory/ca.crt" -CAkey "$directory/ca.key" -CAcreateserial \
  -extfile "$extension_file" -out "$directory/mcp.crt"
rm -f "$directory/mcp.csr"
openssl verify -CAfile "$directory/ca.crt" "$directory/mcp.crt"
for ip in "$@"; do
  openssl x509 -in "$directory/mcp.crt" -noout -checkip "$ip"
done
echo "CA certificate: $directory/ca.crt"
echo "Server certificate: $directory/mcp.crt"
echo "Keep ca.key and mcp.key on the host; do not copy them into the sandbox."
