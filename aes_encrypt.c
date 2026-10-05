#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include "tables.h"

/* Cyclic row shifting on the 16-byte state matrix */
static void ShiftRows(uint8_t *state) {
    uint8_t state_copy[KEY_SIZE];
    memcpy(state_copy, state, KEY_SIZE);
    for (int i = 0; i < KEY_SIZE; i++)
        state[i] = state_copy[(i * (STATE_NB_ROW + 1)) % KEY_SIZE];
}

/* Evaluates a masked 32-bit addition through precomputed bit-level XOR lookup tables */
static inline uint32_t XOR32(uint32_t a, uint32_t b, int round, int xor_index) {
    uint32_t res = 0;

    for (int bit = 0; bit < NB_XOR_BITS; bit++) {
        uint8_t ba = (a >> (31 - bit)) & 1U;
        uint8_t bb = (b >> (31 - bit)) & 1U;
        res ^= XOR_BIT_TABLES[round][xor_index][bit][ba][bb];
    }

    return res;
}

static void print_hex(const uint8_t *key, int length) {
    for (int i = 0; i < length; i++) {
        printf("%02X", key[i]);
        if ((i + 1) % KEY_SIZE == 0)
            printf("\n");
    }
}

/* White-Box AES encryption execution using precomputed tables */
static void AES_128_WB(uint8_t *state, int fault_byte, uint8_t fault_xor, bool quiet) {
    /* Rounds 1 to 9: ShiftRows, 4 CTY lookups per column, and 3-node XOR addition */
    for (int r = 0; r < NB_ROUNDS - 1; r++) {
        /* Optional round-9 single-byte fault injection for DFA cryptanalysis */
        if ((r + 1) == (NB_ROUNDS - 1) && fault_byte >= 0 && fault_byte < KEY_SIZE && fault_xor != 0) {
            state[fault_byte] ^= fault_xor;
            if (!quiet)
                printf("fault[r=%d,b=%d,x=0x%02X]\n", r + 1, fault_byte, fault_xor);
        }

        ShiftRows(state);

        uint8_t new_state[KEY_SIZE];
        for (int c = 0; c < STATE_NB_ROW; c++) {
            const int x0 = 3 * c;
            const int x1 = x0 + 1;
            const int x2 = x0 + 2;

            /* CTY table lookups compute SubBytes, AddRoundKey, and MixColumns */
            uint32_t v0 = CTY_TABLES[r][0][c][state[c * STATE_NB_ROW + 0]];
            uint32_t v1 = CTY_TABLES[r][1][c][state[c * STATE_NB_ROW + 1]];
            uint32_t v2 = CTY_TABLES[r][2][c][state[c * STATE_NB_ROW + 2]];
            uint32_t v3 = CTY_TABLES[r][3][c][state[c * STATE_NB_ROW + 3]];

            /* Execution trace collection for DCA attack */
            if (r == 0) {
                if (c == 0)
                    printf("TRACE ");
                printf("%08x%08x%08x%08x", v0, v1, v2, v3);
                if (c == STATE_NB_ROW - 1)
                    printf("\n");
            }

            /* 3-node binary XOR tree: combines 4 rows into a 32-bit column word */
            uint32_t left = XOR32(v0, v1, r, x0);
            uint32_t right = XOR32(v2, v3, r, x1);
            uint32_t acc = XOR32(left, right, r, x2);

            /* Unpack 32-bit column word into 4 bytes */
            for (int i = 0; i < STATE_NB_ROW; i++)
                new_state[c * STATE_NB_ROW + i] = (acc >> (NB_XOR_NIBBLES * (STATE_NB_ROW - 1 - i))) & 0xff;
        }
        memcpy(state, new_state, KEY_SIZE);

        if (!quiet) {
            printf("round[%d].n_col\t", r + 1);
            print_hex(state, KEY_SIZE);
        }
    }

    /* Round 10: ShiftRows and final T-box lookup (no MixColumns) */
    ShiftRows(state);
    for (int i = 0; i < KEY_SIZE; i++)
        state[i] = FINAL_T_BOX[i][state[i]];
}

static void usage(const char *prog_name) {
    fprintf(stderr,
            "Usage: %s <plaintext:32-hex> [--fault-byte B --fault-xor X] [--quiet]\n"
            "  <plaintext:32-hex> must be exactly %d hex characters (0-9, a-f, A-F)\n"
            "  B: byte index in [0, %d]\n"
            "  X: fault XOR value in [1, 255] (decimal or hex)\n"
            "  Fault model injects at round %d input.\n",
            prog_name, KEY_SIZE * 2, KEY_SIZE - 1, NB_ROUNDS - 1);
}

int main(int argc, char *argv[]) {
    if (argc < 2 || strlen(argv[1]) != KEY_SIZE * 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    int fault_byte = -1;
    long fault_xor_long = 0;
    bool fault_byte_seen = false;
    bool fault_xor_seen = false;
    bool quiet = false;

    for (int i = 2; i < argc; ) {
        if (strcmp(argv[i], "--fault-byte") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            fault_byte = (int)strtol(argv[i + 1], NULL, 0);
            fault_byte_seen = true;
            i += 2;
        } else if (strcmp(argv[i], "--fault-xor") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            fault_xor_long = strtol(argv[i + 1], NULL, 0);
            fault_xor_seen = true;
            i += 2;
        } else if (strcmp(argv[i], "--quiet") == 0) {
            quiet = true;
            i++;
        } else {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (fault_byte_seen || fault_xor_seen) {
        if (!(fault_byte_seen && fault_xor_seen)) {
            fprintf(stderr, "error: --fault-byte and --fault-xor must be specified together\n");
            usage(argv[0]);
            return EXIT_FAILURE;
        }

        if (fault_byte < 0 || fault_byte >= KEY_SIZE || fault_xor_long <= 0 || fault_xor_long > 0xFF) {
            fprintf(stderr, "error: invalid fault parameters\n");
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    uint8_t input[KEY_SIZE];
    for (int i = 0; i < KEY_SIZE; i++) {
        if (sscanf(&argv[1][i * 2], "%2hhx", &input[i]) != 1) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    AES_128_WB(input, fault_byte, (uint8_t)fault_xor_long, quiet);

    if (!quiet)
        printf("Encoded input:\t");
    print_hex(input, KEY_SIZE);

    return EXIT_SUCCESS;
}
