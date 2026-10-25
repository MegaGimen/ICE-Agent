#!/usr/bin/env bash
set -euo pipefail

# Read-only preflight for the authorized GB10 offline media. Run before install.
if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <ice_offline_bundle.tar> <ice_models directory>" >&2
  exit 2
fi
bundle="$1"
models="$2"
expected="1c988f3a590ec04b15c1f48777a6ce1ce9302823c93670ea81a7b929284d985a"
if [[ ! -f "$bundle" || ! -d "$models" ]]; then
  echo "Bundle file or model directory is missing" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$bundle" | cut -d ' ' -f 1)"
else
  actual="$(shasum -a 256 "$bundle" | cut -d ' ' -f 1)"
fi
if [[ "$actual" != "$expected" ]]; then
  echo "Offline bundle SHA-256 mismatch" >&2
  exit 1
fi
echo "Offline bundle SHA-256 matches the plan"

required=(
  models--nvidia--Qwen3.6-35B-A3B-NVFP4
  models--jaredpalmer--kev-27b
  models--Qwen--Qwen3.8-27B
  models--BAAI--bge-m3
)
missing=0
for entry in "${required[@]}"; do
  if [[ -d "$models/$entry" ]]; then
    echo "Found $entry"
  else
    echo "Missing $entry" >&2
    missing=1
  fi
done
for entry in models--jaredpalmer--kev-9b models--Qwen--Qwen3.5-9B-Base; do
  if [[ -d "$models/$entry" ]]; then
    echo "Found optional fallback $entry"
  else
    echo "Optional fallback missing: $entry"
  fi
done
exit "$missing"
