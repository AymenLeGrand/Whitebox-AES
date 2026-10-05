#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

generate_random_hex() {
    head -c 16 /dev/urandom | xxd -p | tr -d ' \n'
}

run_test() {
    local plaintext="$1"
    local key="$2"

    echo " * Testing Plaintext: ${plaintext}"
    echo " * Testing Key:       ${key}"

    local aes_out
    aes_out=$(./aes "$key" "$plaintext" | tail -n 1 | grep -oE '[0-9a-fA-F]{32}')

    ./aes_whitener "$key" > /dev/null

    rm -f aes_encrypt
    make aes_encrypt > /dev/null

    local wb_out
    wb_out=$(./aes_encrypt "$plaintext" | tail -n 1 | grep -oE '[0-9a-fA-F]{32}')

    if [[ "${aes_out^^}" == "${wb_out^^}" ]]; then
        echo "   [OK] Match: ${aes_out}"
    else
        echo "   [FAIL] Mismatch!"
        echo "   Standard AES: ${aes_out}"
        echo "   White-Box   : ${wb_out}"
        exit 1
    fi
}

if [[ "${1:-}" == "--random" || "${1:-}" == "-random" ]]; then
    count="${2:-20}"
    echo "[*] Compiling base binaries..."
    make clean > /dev/null
    make aes aes_whitener > /dev/null

    for i in $(seq 1 "$count"); do
        echo "--- Test $i / $count ---"
        pt=$(generate_random_hex)
        k=$(generate_random_hex)
        run_test "$pt" "$k"
    done
    echo ""
    echo "[+] All $count test vectors passed successfully."
else
    if [[ $# -ne 2 ]]; then
        echo "Usage: $0 <plaintext:32-hex> <key:32-hex>"
        echo "   or: $0 --random [count] (default: 20 tests)"
        exit 1
    fi

    echo "[*] Compiling base binaries..."
    make clean > /dev/null
    make aes aes_whitener > /dev/null
    run_test "$1" "$2"
fi
