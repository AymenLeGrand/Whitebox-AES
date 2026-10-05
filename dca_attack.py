#!/usr/bin/env python3
"""
Differential Computation Analysis (DCA) on AES-128

Implements software side-channel cryptanalysis (Bos et al., CHES 2016) against
White-Box AES implementations. The attack correlates internal execution state bits
(recorded during CTY table lookups in round 1) with hypothesized Hamming weight
leakages of intermediate state values: HW(SBox(P_i ^ K_i)).
The key byte candidate maximizing Pearson correlation is selected for each position.
"""

import argparse
import sys
from pathlib import Path
import numpy as np

SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

HAMMING_WEIGHTS = np.array([bin(n).count('1') for n in range(256)], dtype=np.float64)


def shift_rows_idx(i):
    return (i * 5) % 16


def load_traces(traces_file):
    path = Path(traces_file)
    if not path.is_file():
        raise FileNotFoundError(f"Traces file '{traces_file}' not found")

    plaintexts = []
    traces = []

    with open(path, "r", encoding="ascii") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) != 2:
                continue

            pt_raw = bytes.fromhex(parts[0])
            trace_raw = bytes.fromhex(parts[1])

            state = bytearray(16)
            for i in range(16):
                state[i] = pt_raw[shift_rows_idx(i)]
            plaintexts.append(state)

            bits = []
            for byte_val in trace_raw:
                for bit_pos in range(7, -1, -1):
                    bits.append((byte_val >> bit_pos) & 1)
            traces.append(bits)

    if not plaintexts:
        raise ValueError(f"No valid traces parsed from '{traces_file}'")

    return plaintexts, np.array(traces, dtype=np.float64)


def attack_key(plaintexts, traces_np):
    num_traces, num_bits = traces_np.shape
    print(f"Loaded {num_traces} traces ({num_bits} execution bits per trace)")

    recovered_shifted = [0] * 16

    for byte_idx in range(16):
        target_bits = traces_np[:, byte_idx * 32 : (byte_idx + 1) * 32]
        max_corr = -1.0
        best_key_byte = 0

        for candidate_key in range(256):
            hypotheses = [HAMMING_WEIGHTS[SBOX[pt[byte_idx] ^ candidate_key]] for pt in plaintexts]
            hyp_arr = np.array(hypotheses, dtype=np.float64)

            # Compute correlation with all 32 bits of this byte's execution slice
            corrs = []
            for bit_col in range(32):
                corr_matrix = np.corrcoef(hyp_arr, target_bits[:, bit_col])
                c = abs(corr_matrix[0, 1])
                if not np.isnan(c):
                    corrs.append(c)

            if corrs:
                top_corr = max(corrs)
                if top_corr > max_corr:
                    max_corr = top_corr
                    best_key_byte = candidate_key

        recovered_shifted[byte_idx] = best_key_byte
        print(f"  Byte {byte_idx:2d}: best candidate = 0x{best_key_byte:02X} (correlation = {max_corr:.4f})")

    recovered_key = [0] * 16
    for i in range(16):
        recovered_key[shift_rows_idx(i)] = recovered_shifted[i]

    master_key_hex = "".join(f"{b:02X}" for b in recovered_key)
    print(f"\n[+] Recovered Master Key: {master_key_hex}")
    return master_key_hex


def main():
    parser = argparse.ArgumentParser(description="Differential Computation Analysis (DCA) key recovery")
    parser.add_argument("--traces", default="traces.txt", help="Path to trace file (default: traces.txt)")
    args = parser.parse_args()

    try:
        plaintexts, traces_np = load_traces(args.traces)
        attack_key(plaintexts, traces_np)
    except Exception as exc:
        print(f"[-] Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
