# White-Box AES-128: Implementation & Cryptanalysis (DFA & DCA)

A C and Python implementation of White-Box AES-128 based on the Chow et al. framework, accompanied by automated practical cryptanalysis tools demonstrating **Differential Fault Analysis (DFA)** and **Differential Computation Analysis (DCA)**.

---

## Overview

In a white-box attack model, the adversary has total visibility and execution control over the cryptographic software—they can inspect memory, alter registers, observe intermediate values, and inject faults at arbitrary points during execution.

This project implements:
1. **White-Box AES-128 (Chow et al. scheme)**: Embeds the 128-bit secret key into precomputed lookup tables ($T$-boxes, $Ty$-boxes, $CTY$-tables, and bit-level XOR trees) obfuscated using dual non-linear nibble masking and 32-bit linear mixing bijections.
2. **Differential Fault Analysis (DFA)**: An automated fault-injection attack following the Piret & Quisquater model on round 9, recovering the master key with only a handful of faults.
3. **Differential Computation Analysis (DCA)**: A software side-channel attack (Bos et al., CHES 2016) measuring correlation between software execution traces and predicted Hamming weights to extract the secret key without reverse-engineering the table masks.

---

## Architecture & Design

### 1. Table Composition & Lookup Network

Standard AES operations (SubBytes, ShiftRows, MixColumns, AddRoundKey) are collapsed into cascaded lookup tables:

- **$T$-Boxes ($T_i^r$)**: Fuse round key addition and SubBytes:
  $$T_i^r(x) = S(x \oplus k_i^r)$$
- **$Ty$-Boxes**: Precompute Galois Field multiplication for the MixColumns linear transformation:
  $$Ty(x) = MC \cdot x \in \mathbb{F}_{2^8}^4$$
- **$CTY$-Tables**: Merge $T$-boxes and $Ty$-boxes into 32-bit output lookups for rounds 1 through 9:
  $$CTY_{y,c}^r(x) = Ty_y(T_{c \cdot 4 + y}^r(x))$$
- **Bit-Level XOR Trees**: Since 32-bit additions cannot use a single $2^{64}$-entry lookup table, column additions are evaluated through a 3-node binary tree of bit-level XOR lookups.

### 2. White-Box Defenses

To prevent direct extraction of the round keys from the tables, two layers of obfuscation are applied:
- **Non-Linear Nibble Masking**: Random 4-bit masks ($M_{CTY}$ and $M_{XOR}$) are generated per round and applied between table outputs and subsequent table inputs. The input mask of stage $r+1$ perfectly cancels the output mask of stage $r$.
- **Linear Mixing Bijections**: A random 32-bit permutation is applied to each column's intermediate state. The bit routing is inverted at the root of the XOR tree, hiding intermediate algebraic structures.

---

## Practical Cryptanalysis

### Differential Fault Analysis (DFA)
- **Model**: Single-byte fault injection at the input of round 9 (prior to round 9 MixColumns).
- **Mechanism**: A single faulted byte diffuses across exactly 4 bytes in a single column after round 9 MixColumns. Because round 10 has no MixColumns (only SubBytes and AddRoundKey), the differential relationship between reference and faulty ciphertexts satisfies:
  $$S^{-1}(C_i \oplus K_{10,i}) \oplus S^{-1}(C^*_i \oplus K_{10,i}) = \lambda_i \cdot \delta$$
  where $\lambda_i \in \{1, 2, 3\}$ are MixColumns matrix coefficients and $\delta$ is the unknown non-zero fault difference.
- **Recovery**: Candidate hypotheses for the four round-10 key bytes are intersected across multiple faults. Once round 10 key $K_{10}$ is isolated, the AES key schedule is inverted to recover the master key $K_0$.

### Differential Computation Analysis (DCA)
- **Model**: Software execution trace side-channel (Bos et al., CHES 2016).
- **Mechanism**: While white-box masking hides explicit round keys, intermediate software execution traces (memory lookups, register states) correlate with the Hamming weight of intermediate sensitive variables.
- **Leakage Model**: The attack correlates recorded execution bit traces with the hypothesized Hamming weight after the first round S-box:
  $$HW(SBox(P_i \oplus K_i))$$
- **Recovery**: Computing the Pearson correlation coefficient over traces for all 256 key candidates per byte uniquely identifies the correct key byte having the maximum correlation peak.

---

## Project Structure

```
├── aes.c             # Standard AES-128 reference implementation & table verification
├── aes_whitener.c    # Generator: computes masked lookup tables and exports tables.h
├── aes_encrypt.c     # White-box AES cipher executable (with fault injection & trace instrumentation)
├── dfa_attack.py     # Piret-Quisquater DFA attack implementation & verification
├── dca_attack.py     # DCA correlation attack implementation using NumPy
├── test_wb.sh        # Differential test suite comparing White-Box against reference AES
├── run_dfa.sh        # Automated DFA test harness across multiple keys and plaintexts
├── run_dca.sh        # Automated trace acquisition and DCA key recovery runner
├── Makefile          # Build recipes
└── .gitignore        # Ignored binaries, headers, traces, and temporary files
```

---

## Getting Started

### Prerequisites

- **C Compiler**: GCC or Clang (supporting C11, e.g., `gcc >= 9.0`)
- **Make**: GNU Make
- **Python**: Python 3.8+ with `numpy`
- **Unix utilities**: `bash`, `xxd`, `head`

Install Python dependencies:
```bash
pip install numpy
```

### Building the Project

Compile the reference AES implementation and the table generator:
```bash
make all
```

To clean all build artifacts and logs:
```bash
make clean
```

---

## Usage & Verification

### 1. Generating a White-Box Instance & Encrypting

Generate the lookup tables header (`tables.h`) for a selected 128-bit key (32 hex characters):
```bash
./aes_whitener 000102030405060708090a0b0c0d0e0f
```

Compile the white-box encryption binary embedding the generated tables:
```bash
make aes_encrypt
```

Encrypt a 128-bit plaintext:
```bash
./aes_encrypt 00112233445566778899aabbccddeeff
```

### 2. Differential Testing

Validate that the white-box implementation produces identical ciphertexts to reference AES across 50 random key/plaintext pairs:
```bash
./test_wb.sh --random 50
```

---

## Running Cryptanalysis

### Running Differential Fault Analysis (DFA)

Execute the full automated DFA attack test harness:
```bash
./run_dfa.sh --max-xor 16
```

Or run the DFA attack directly against a single instance:
```bash
# 1. Generate tables and compile cipher
./aes_whitener 000102030405060708090A0B0C0D0E0F
make aes_encrypt

# 2. Collect faults and extract key
python3 dfa_attack.py run --plaintext 00112233445566778899aabbccddeeff --max-xor 16
```

Expected output:
```text
[collect] dfa_printf_log.csv g0=16 g1=16 g2=16 g3=16 noise=0
[analyze] used={'0': 16, '1': 16, '2': 16, '3': 16} pool={0:1, 1:1, 2:1, 3:1}
[result] round10=13111D7FE3944A17F307A78B4D2B30C5
[result] master=000102030405060708090A0B0C0D0E0F
[verify] ok
```

### Running Differential Computation Analysis (DCA)

Execute automated trace collection and key recovery:
```bash
./run_dca.sh 1000
```

This collects 1,000 execution traces and evaluates the Pearson correlation coefficient for all 256 candidates across each of the 16 key bytes.

---

## References

1. **Chow, S., Eisen, P., Johnson, H., & van Oorschot, P. C.** (2002). *White-Box Cryptography and an AES Implementation*. Selected Areas in Cryptography (SAC 2002).
2. **Piret, G., & Quisquater, J. J.** (2003). *A Fault Countermeasure for AES Vulnerable to a New Differential Fault Analysis*. Cryptographic Hardware and Embedded Systems (CHES 2003).
3. **Bos, J. W., Hubain, C., Michiels, W., & Teuwen, P.** (2016). *Differential Computation Analysis: Hiding your Keys into Software is Not Enough*. Cryptographic Hardware and Embedded Systems (CHES 2016).

---

## License

This project is licensed under the MIT License.
