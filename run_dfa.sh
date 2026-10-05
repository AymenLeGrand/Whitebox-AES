#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

MAX_XOR=32
CLEANUP_LOGS=false

DEFAULT_KEYS=(
  "000102030405060708090A0B0C0D0E0F"
  "2B7E151628AED2A6ABF7158809CF4F3C"
)

DEFAULT_PTS=(
  "00112233445566778899aabbccddeeff"
  "00000000000000000000000000000000"
  "ffffffffffffffffffffffffffffffff"
)

USER_KEYS=()
USER_PTS=()

usage() {
  cat <<'EOF'
Usage: ./run_dfa.sh [options]

Options:
  --max-xor N          Try xor values 1..N for each faulted byte (default: 32)
  --key HEX32          Add one init key (repeatable)
  --pt HEX32           Add one plaintext block (repeatable)
  --cleanup-logs       Delete csv logs for passing tests
  --help               Show this help

If no --key or --pt are provided, built-in defaults are used.
EOF
}

is_hex32() {
  [[ "$1" =~ ^[0-9A-Fa-f]{32}$ ]]
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --max-xor)
      [[ $# -ge 2 ]] || { echo "missing value for --max-xor"; exit 2; }
      MAX_XOR="$2"
      shift 2
      ;;
    --key)
      [[ $# -ge 2 ]] || { echo "missing value for --key"; exit 2; }
      USER_KEYS+=("$2")
      shift 2
      ;;
    --pt)
      [[ $# -ge 2 ]] || { echo "missing value for --pt"; exit 2; }
      USER_PTS+=("$2")
      shift 2
      ;;
    --cleanup-logs)
      CLEANUP_LOGS=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1"
      usage
      exit 2
      ;;
  esac
done

[[ "$MAX_XOR" =~ ^[0-9]+$ ]] || { echo "--max-xor must be an integer"; exit 2; }

KEYS=("${DEFAULT_KEYS[@]}")
PTS=("${DEFAULT_PTS[@]}")

if [[ ${#USER_KEYS[@]} -gt 0 ]]; then
  KEYS=("${USER_KEYS[@]}")
fi

if [[ ${#USER_PTS[@]} -gt 0 ]]; then
  PTS=("${USER_PTS[@]}")
fi

for k in "${KEYS[@]}"; do
  is_hex32 "$k" || { echo "invalid --key value (need 32 hex): $k"; exit 2; }
done

for p in "${PTS[@]}"; do
  is_hex32 "$p" || { echo "invalid --pt value (need 32 hex): $p"; exit 2; }
done

echo "[setup] max_xor=$MAX_XOR fault_round=9 cleanup_logs=$CLEANUP_LOGS"
echo "[setup] keys=${#KEYS[@]} plaintexts=${#PTS[@]}"

PASS=0
FAIL=0

for key in "${KEYS[@]}"; do
  key_up="${key^^}"
  echo "=== init key $key_up ==="

  make clean >/dev/null
  make aes aes_whitener >/dev/null
  ./aes_whitener "$key_up" >/dev/null
  make aes_encrypt >/dev/null

  for pt in "${PTS[@]}"; do
    pt_low="${pt,,}"
    log_file="dfa_${key_up:0:8}_${pt_low:0:8}.csv"

    out="$(python3 dfa_attack.py run --plaintext "$pt_low" --max-xor "$MAX_XOR" --log-file "$log_file" 2>&1 || true)"

    rec="$(printf '%s\n' "$out" | sed -n 's/^\[result\] master=//p' | tail -n 1 | tr '[:lower:]' '[:upper:]')"
    ver="$(printf '%s\n' "$out" | sed -n 's/^\[verify\] //p' | tail -n 1)"

    if [[ "$rec" == "$key_up" && "$ver" == "ok" ]]; then
      echo "PASS key=$key_up pt=$pt_low"
      PASS=$((PASS + 1))
      if [[ "$CLEANUP_LOGS" == true ]]; then
        rm -f "$log_file"
      fi
    else
      echo "FAIL key=$key_up pt=$pt_low recovered=${rec:-<none>} verify=${ver:-<none>}"
      printf '%s\n' "$out" > "dfa_fail_${key_up:0:8}_${pt_low:0:8}.log"
      FAIL=$((FAIL + 1))
    fi
  done
done

echo "[summary] pass=$PASS fail=$FAIL"

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
