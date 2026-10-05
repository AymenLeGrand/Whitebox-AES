#!/usr/bin/env python3
"""
Differential Fault Analysis (DFA) on AES-128 (Piret & Quisquater Attack)

This script implements fault collection and key recovery against a White-Box
AES-128 implementation. A single-byte fault injected at round 9 input diffuses
into four ciphertext bytes after round 9 MixColumns. By comparing faulty
ciphertexts to the reference ciphertext, candidate round-10 key bytes are
identified and intersected until a unique 128-bit round-10 key is determined.
Inverting the key schedule yields the original master key.
"""

import argparse
import csv
import re
import subprocess
from pathlib import Path

DEFAULT_PLAINTEXT = "00112233445566778899aabbccddeeff"

# ShiftRows column groups: bytes affected together by a fault in column 0..3
COLUMN_GROUPS = [
    [0, 7, 10, 13],
    [1, 4, 11, 14],
    [2, 5, 8, 15],
    [3, 6, 9, 12],
]

GROUP_MASKS = [tuple(i in group for i in range(16)) for group in COLUMN_GROUPS]

# MixColumns matrix row permutations for Piret-Quisquater candidate equations
TRANS_MATRIX = [
    [2, 3, 1, 1],
    [3, 1, 1, 2],
    [1, 1, 2, 3],
    [1, 2, 3, 1],
]

RCON = [1, 2, 4, 8, 16, 32, 64, 128, 0x1B, 0x36]


def gf_mul(a, b):
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        a = ((a << 1) & 0xFF) ^ (0x1B if (a & 0x80) else 0)
        b >>= 1
    return res


def gf_inv(x):
    if x == 0:
        return 0
    for y in range(1, 256):
        if gf_mul(x, y) == 1:
            return y
    return 0


def aes_sbox(x):
    a = gf_inv(x)
    y = a
    for _ in range(4):
        a = ((a << 1) | (a >> 7)) & 0xFF
        y ^= a
    return y ^ 0x63


SBOX = [aes_sbox(i) for i in range(256)]
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

INV_GF_MUL = {m: [0] * 256 for m in (1, 2, 3)}
for m, table in INV_GF_MUL.items():
    for e in range(256):
        table[gf_mul(m, e)] = e


def run_wb(root, pt, fault_byte=None, fault_xor=None):
    binary = "./aes_encrypt" if (root / "aes_encrypt").exists() else "./wb_aes"
    cmd = [binary, pt, "--quiet"]
    if fault_byte is not None:
        cmd += ["--fault-byte", str(fault_byte), "--fault-xor", str(fault_xor)]

    out = subprocess.check_output(cmd, cwd=str(root), text=True, stderr=subprocess.STDOUT)
    matches = re.findall(r"[0-9A-Fa-f]{32}", out)
    if not matches:
        raise SystemExit(f"{binary} output missing ciphertext")
    return bytes.fromhex(matches[-1])


def classify_fault(ref, faulty):
    diff_mask = tuple((a ^ b) != 0 for a, b in zip(ref, faulty))
    if sum(diff_mask) != 4:
        return -1
    for group_idx, want in enumerate(GROUP_MASKS):
        if diff_mask == want:
            return group_idx
    return -1


def find_candidates(ref, faulty, group_idx):
    positions = COLUMN_GROUPS[group_idx]
    candidates = []
    seen = set()

    for tm in TRANS_MATRIX:
        per_pos = []
        for j, pos in enumerate(positions):
            diff_to_keys = {}
            inv_m = INV_GF_MUL[tm[j]]
            ref_byte, bad_byte = ref[pos], faulty[pos]

            for k in range(256):
                delta = inv_m[INV_SBOX[ref_byte ^ k] ^ INV_SBOX[bad_byte ^ k]]
                diff_to_keys.setdefault(delta, set()).add(k)
            per_pos.append(diff_to_keys)

        common_deltas = set(per_pos[0]) & set(per_pos[1]) & set(per_pos[2]) & set(per_pos[3])
        for delta in common_deltas:
            cand = tuple(set(diff_to_keys[delta]) for diff_to_keys in per_pos)
            key = tuple(frozenset(s) for s in cand)
            if key not in seen:
                seen.add(key)
                candidates.append(cand)

    return candidates


def merge_candidates(existing, new, cap=2000):
    if not existing:
        return new

    out = []
    seen = set()
    for a in existing:
        for b in new:
            intersected = tuple(a[i] & b[i] for i in range(4))
            if not all(intersected):
                continue
            key = tuple(frozenset(s) for s in intersected)
            if key not in seen:
                seen.add(key)
                out.append(intersected)

    if not out:
        return existing
    if len(out) > cap:
        out = sorted(out, key=lambda t: sum(len(s) for s in t))[:cap]
    return out


def invert_key_schedule(round10_key):
    w = [None] * 44
    for i in range(4):
        w[40 + i] = list(round10_key[4 * i : 4 * i + 4])

    for i in range(43, 3, -1):
        if i % 4 == 0:
            rot = w[i - 1][1:] + w[i - 1][:1]
            sub = [SBOX[x] for x in rot]
            sub[0] ^= RCON[i // 4 - 1]
            w[i - 4] = [w[i][j] ^ sub[j] for j in range(4)]
        else:
            w[i - 4] = [w[i][j] ^ w[i - 1][j] for j in range(4)]

    return bytes(w[0] + w[1] + w[2] + w[3])


def collect_faults(root, pt, max_xor, log_file):
    ref = run_wb(root, pt)
    counts = {0: 0, 1: 0, 2: 0, 3: 0, -1: 0}

    with open(log_file, "w", newline="", encoding="ascii") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "fault_byte", "fault_xor", "ciphertext", "group"])
        writer.writerow(["ref", "", "", ref.hex().upper(), "-1"])

        for b in range(16):
            for x in range(1, max_xor + 1):
                faulty = run_wb(root, pt, b, x)
                group = classify_fault(ref, faulty)
                counts[group] += 1
                writer.writerow(["fault", b, x, faulty.hex().upper(), group])

    print(f"[collect] {log_file} g0={counts[0]} g1={counts[1]} g2={counts[2]} g3={counts[3]} noise={counts[-1]}")


def analyze_faults(root, pt, log_file):
    with open(log_file, "r", encoding="ascii") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        print("[analyze] empty log")
        return 1

    ref = bytes.fromhex(rows[0]["ciphertext"])
    pool = {0: [], 1: [], 2: [], 3: []}
    used = {0: 0, 1: 0, 2: 0, 3: 0}
    seen = set()

    for r in rows[1:]:
        try:
            group = int(r["group"])
        except ValueError:
            continue
        if group not in (0, 1, 2, 3):
            continue

        ct_hex = r["ciphertext"].strip().upper()
        if ct_hex in seen:
            continue
        seen.add(ct_hex)

        cands = find_candidates(ref, bytes.fromhex(ct_hex), group)
        if not cands:
            continue

        pool[group] = merge_candidates(pool[group], cands)
        used[group] += 1

    print(f"[analyze] used={used} pool={{0:{len(pool[0])},1:{len(pool[1])},2:{len(pool[2])},3:{len(pool[3])}}}")
    resolved = all(len(pool[g]) == 1 and all(len(s) == 1 for s in pool[g][0]) for g in range(4))
    if not resolved:
        print("[result] unresolved (increase --max-xor and re-collect)")
        return 1

    round10 = [0] * 16
    for g in range(4):
        for j, pos in enumerate(COLUMN_GROUPS[g]):
            round10[pos] = next(iter(pool[g][0][j]))

    round10_bytes = bytes(round10)
    master_key = invert_key_schedule(round10_bytes).hex().upper()

    print(f"[result] round10={round10_bytes.hex().upper()}")
    print(f"[result] master={master_key}")

    out = subprocess.check_output(["./aes", master_key, pt], cwd=str(root), text=True)
    matches = re.findall(r"[0-9A-Fa-f]{32}", out)
    verified = bool(matches) and bytes.fromhex(matches[-1]) == ref
    print(f"[verify] {'ok' if verified else 'failed'}")
    return 0 if verified else 1


def main():
    parser = argparse.ArgumentParser(description="Differential Fault Analysis (DFA) attack against White-Box AES-128")
    parser.add_argument("mode", nargs="?", choices=["run", "collect", "analyze"], default="run")
    parser.add_argument("--plaintext", default=DEFAULT_PLAINTEXT)
    parser.add_argument("--max-xor", type=int, default=255)
    parser.add_argument("--log-file", default="dfa_printf_log.csv")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent
    pt = args.plaintext.strip().lower().replace("0x", "")
    if len(pt) != 32 or any(c not in "0123456789abcdef" for c in pt):
        raise SystemExit("plaintext must be 32 hex chars")
    if not (root / "aes_encrypt").exists() and not (root / "wb_aes").exists():
        raise SystemExit("aes_encrypt binary missing (build it first)")
    if not (root / "aes").exists():
        raise SystemExit("aes missing")

    log_path = root / args.log_file
    if args.mode in ("collect", "run"):
        collect_faults(root, pt, args.max_xor, log_path)
    if args.mode in ("analyze", "run"):
        return analyze_faults(root, pt, log_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())