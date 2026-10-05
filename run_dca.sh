#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

NUM_TRACES="${1:-1000}"

generate_random_hex() {
    head -c 16 /dev/urandom | xxd -p | tr -d ' \n'
}

KEY=$(generate_random_hex)
echo "[*] Target Key: ${KEY}"

echo "[*] Building white-box AES for key..."
make clean > /dev/null
make aes_whitener > /dev/null
./aes_whitener "$KEY" > /dev/null
make aes_encrypt > /dev/null

echo "[*] Collecting ${NUM_TRACES} execution traces..."
(for ((i = 1; i <= NUM_TRACES; i++)); do
    head -c 16 /dev/urandom | xxd -p | tr -d ' \n'
    echo ""
done) | while read -r pt; do
    printf "%s " "$pt"
    ./aes_encrypt "$pt" --quiet | grep "TRACE" | awk '{print $2}'
done > traces.txt

echo "[*] Running DCA correlation attack..."
python3 dca_attack.py --traces traces.txt
