#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <err.h>

#define KEY_SIZE            16
#define KEY_LENGTH_W        (KEY_SIZE / 4)
#define ALL_BYTES_FOR_KEY   (KEY_SIZE * KEY_SIZE)
#define STATE_NB_ROW        4
#define NB_ROUNDS           10
#define NB_XOR_PER_ROUND    12
#define NB_XOR_NIBBLES      8
#define MIX_BITS            32
#define NB_XOR_BITS         MIX_BITS

#define WHITEBOX_HEADER     "tables.h"
#define COMMA_IF(check)     ((check) ? "," : "")

/* Random 4-bit nibble masks used to obscure intermediate table values between stages */
static uint8_t M_CTY[NB_ROUNDS][STATE_NB_ROW][NB_XOR_NIBBLES];
static uint8_t M_XOR[NB_ROUNDS][NB_XOR_PER_ROUND][NB_XOR_NIBBLES];

/* White-box lookup tables */
static uint8_t T_BOXES[NB_ROUNDS][KEY_SIZE][ALL_BYTES_FOR_KEY];
static uint8_t FINAL_T_BOX[KEY_SIZE][ALL_BYTES_FOR_KEY];
static uint32_t TY_TABLES[STATE_NB_ROW][ALL_BYTES_FOR_KEY];
static uint32_t CTY_TABLES[NB_ROUNDS - 1][STATE_NB_ROW][STATE_NB_ROW][ALL_BYTES_FOR_KEY];
static uint32_t XOR_BIT_TABLES[NB_ROUNDS - 1][NB_XOR_PER_ROUND][NB_XOR_BITS][2][2];
static uint8_t MIX_POS[NB_ROUNDS - 1][STATE_NB_ROW][MIX_BITS];

/* AES MixColumns MDS matrix */
static const uint8_t MC[STATE_NB_ROW][STATE_NB_ROW] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};

/* Round constants for key schedule */
static const uint8_t Rcon[NB_ROUNDS][STATE_NB_ROW] = {
    {0x01, 0x00, 0x00, 0x00},
    {0x02, 0x00, 0x00, 0x00},
    {0x04, 0x00, 0x00, 0x00},
    {0x08, 0x00, 0x00, 0x00},
    {0x10, 0x00, 0x00, 0x00},
    {0x20, 0x00, 0x00, 0x00},
    {0x40, 0x00, 0x00, 0x00},
    {0x80, 0x00, 0x00, 0x00},
    {0x1B, 0x00, 0x00, 0x00},
    {0x36, 0x00, 0x00, 0x00}
};

/* Rijndael S-Box */
static const uint8_t SBox[ALL_BYTES_FOR_KEY] = {
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
};

/* Generates non-linear 4-bit masking vectors */
static void init_masks(void) {
    srand(time(NULL) ^ (getpid() << 16));

    for (int r = 0; r < NB_ROUNDS; r++) {
        for (int y = 0; y < STATE_NB_ROW; y++) {
            for (int n = 0; n < NB_XOR_NIBBLES; n++)
                M_CTY[r][y][n] = rand() & 0xF;
        }
        for (int x = 0; x < NB_XOR_PER_ROUND; x++) {
            for (int n = 0; n < NB_XOR_NIBBLES; n++)
                M_XOR[r][x][n] = rand() & 0xF;
        }
    }
}

static void RotWord(uint8_t *word) {
    uint8_t tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}

static void SubWord(uint8_t *word) {
    for (int i = 0; i < KEY_LENGTH_W; i++)
        word[i] = SBox[word[i]];
}

/* Key expansion to derive all round keys from master key */
static void KeyExpansion(const uint8_t *key, uint8_t res[NB_ROUNDS + 1][KEY_SIZE]) {
    uint8_t w[(NB_ROUNDS + 1) * KEY_SIZE];
    memcpy(w, key, KEY_SIZE);

    int i = KEY_LENGTH_W;
    uint8_t temp[STATE_NB_ROW];
    while (i <= ((STATE_NB_ROW * NB_ROUNDS) + 3)) {
        memcpy(temp, &w[(i - 1) * STATE_NB_ROW], 4);
        if (i % KEY_LENGTH_W == 0) {
            RotWord(temp);
            SubWord(temp);
            int rcon_index = (i / KEY_LENGTH_W) - 1;

            for (int j = 0; j < STATE_NB_ROW; j++)
                temp[j] ^= Rcon[rcon_index][j];
        } else if ((KEY_LENGTH_W > 6) && (i % KEY_LENGTH_W == 4)) {
            SubWord(temp);
        }

        for (int j = 0; j < 4; j++)
            w[i * 4 + j] = w[(i - KEY_LENGTH_W) * 4 + j] ^ temp[j];

        i++;
    }

    for (int r = 0; r < NB_ROUNDS + 1; r++) {
        for (int j = 0; j < KEY_SIZE; j++)
            res[r][j] = w[r * KEY_SIZE + j];
    }
}

static void ShiftRows(uint8_t *state) {
    uint8_t state_copy[KEY_SIZE];
    memcpy(state_copy, state, KEY_SIZE);
    for (int i = 0; i < KEY_SIZE; i++)
        state[i] = state_copy[(i * 5) % KEY_SIZE];
}

static uint8_t MultGF128(uint8_t x, uint8_t y) {
    if (y == 1)
        return x;

    uint8_t res = x << 1;
    if (x & 0x80)
        res ^= 0x1b;

    if (y == 3)
        res ^= x;

    return res;
}

static uint32_t MatrixMult(int b, uint8_t x) {
    uint32_t res = 0;
    uint8_t temp[STATE_NB_ROW] = {0};
    for (int i = 0; i < STATE_NB_ROW; i++)
        temp[i] = MultGF128(x, MC[i][b]);

    for (int i = 0; i < STATE_NB_ROW; i++)
        res |= (uint32_t)temp[i] << (24 - (i * 8));

    return res;
}

/* Permutes bits according to mixing bijection mapping */
static uint32_t apply_bit_permutation(uint32_t x, const uint8_t perm[MIX_BITS]) {
    uint32_t y = 0;
    for (int dst = 0; dst < MIX_BITS; dst++) {
        uint32_t bit = (x >> (31 - perm[dst])) & 1U;
        y |= bit << (31 - dst);
    }
    return y;
}

static inline uint8_t get_nibble_mask_bit(uint8_t nibble_mask, int bit_index_in_nibble) {
    return (uint8_t)((nibble_mask >> (3 - bit_index_in_nibble)) & 1U);
}

static inline uint8_t get_mask_bit(const uint8_t masks[NB_XOR_NIBBLES], int bit_index) {
    int nibble = bit_index / 4;
    int bit_in_nibble = bit_index % 4;
    return get_nibble_mask_bit(masks[nibble], bit_in_nibble);
}

/* Generates random 32-bit linear bit permutations for each round column */
static void init_mix_bijections(void) {
    for (int r = 0; r < NB_ROUNDS - 1; r++) {
        for (int c = 0; c < STATE_NB_ROW; c++) {
            for (int i = 0; i < MIX_BITS; i++)
                MIX_POS[r][c][i] = (uint8_t)i;

            /* Fisher-Yates shuffle */
            for (int i = MIX_BITS - 1; i > 0; i--) {
                int j = rand() % (i + 1);
                uint8_t tmp = MIX_POS[r][c][i];
                MIX_POS[r][c][i] = MIX_POS[r][c][j];
                MIX_POS[r][c][j] = tmp;
            }
        }
    }
}

/* Precomputes T-boxes fusing AddRoundKey and SubBytes, canceling incoming round masks */
static void init_t_boxes(uint8_t keys[NB_ROUNDS + 1][KEY_SIZE]) {
    uint8_t shifted_key[KEY_SIZE];

    /* Rounds 1 to 9 */
    for (int r = 1; r <= NB_ROUNDS - 1; r++) {
        memcpy(shifted_key, keys[r - 1], KEY_SIZE);
        ShiftRows(shifted_key);

        for (int i = 0; i < KEY_SIZE; i++) {
            uint8_t mask_hi = 0;
            uint8_t mask_lo = 0;

            /* From round 2 onward, unmask state bits coming from previous round's XOR tree */
            if (r > 1) {
                int prev_r = r - 2;
                int prev_pos = (i * 5) % KEY_SIZE;
                int prev_col = prev_pos / STATE_NB_ROW;
                int prev_row = prev_pos % STATE_NB_ROW;
                int prev_final_xor = 3 * prev_col + 2;

                mask_hi = M_XOR[prev_r][prev_final_xor][prev_row * 2];
                mask_lo = M_XOR[prev_r][prev_final_xor][prev_row * 2 + 1];
            }
            uint8_t input_mask = (mask_hi << 4) | mask_lo;

            for (int x = 0; x < ALL_BYTES_FOR_KEY; x++) {
                uint8_t real_x = x ^ input_mask;
                T_BOXES[r - 1][i][x] = SBox[real_x ^ shifted_key[i]];
            }
        }
    }

    /* Round 10 (final round): merges round 9 key and final round 10 key */
    memcpy(shifted_key, keys[NB_ROUNDS - 1], KEY_SIZE);
    ShiftRows(shifted_key);

    for (int i = 0; i < KEY_SIZE; i++) {
        int prev_r = NB_ROUNDS - 2;
        int prev_pos = (i * 5) % KEY_SIZE;
        int prev_col = prev_pos / STATE_NB_ROW;
        int prev_row = prev_pos % STATE_NB_ROW;
        int prev_final_xor = 3 * prev_col + 2;

        uint8_t mask_hi = M_XOR[prev_r][prev_final_xor][prev_row * 2];
        uint8_t mask_lo = M_XOR[prev_r][prev_final_xor][prev_row * 2 + 1];
        uint8_t input_mask = (mask_hi << 4) | mask_lo;

        for (int x = 0; x < ALL_BYTES_FOR_KEY; x++) {
            uint8_t real_x = x ^ input_mask;
            T_BOXES[NB_ROUNDS - 1][i][x] = SBox[real_x ^ shifted_key[i]] ^ keys[NB_ROUNDS][i];
        }
    }
    memcpy(FINAL_T_BOX, T_BOXES[NB_ROUNDS - 1], sizeof(FINAL_T_BOX));
}

/* Precomputes MixColumns 32-bit output lookups */
static void init_ty_tables(void) {
    for (int ty = 0; ty < 4; ty++) {
        for (int x = 0; x < ALL_BYTES_FOR_KEY; x++)
            TY_TABLES[ty][x] = MatrixMult(ty, x);
    }
}

/* Composes T-boxes with Ty-boxes, applying the mixing bijection and CTY output masks */
static void init_cty_tables(void) {
    for (int r = 0; r < NB_ROUNDS - 1; r++) {
        for (int y = 0; y < 4; y++) {
            for (int c = 0; c < 4; c++) {
                int i = c * STATE_NB_ROW + y;

                for (int x = 0; x < ALL_BYTES_FOR_KEY; x++) {
                    uint8_t t = T_BOXES[r][i][x];

                    uint32_t val = TY_TABLES[y][t];
                    val = apply_bit_permutation(val, MIX_POS[r][c]);

                    uint32_t masked_val = 0;
                    for (int n = 0; n < NB_XOR_NIBBLES; n++) {
                        uint8_t nib = (val >> (4 * (7 - n))) & 0xF;
                        nib ^= M_CTY[r][y][n];
                        masked_val |= ((uint32_t)nib) << (4 * (7 - n));
                    }

                    CTY_TABLES[r][y][c][x] = masked_val;
                }
            }
        }
    }
}

/* Precomputes bit-level XOR trees, canceling CTY masks and inverting the mixing permutation */
static void init_xor_tables(void) {
    for (int r = 0; r < NB_ROUNDS - 1; r++) {
        for (int xi = 0; xi < NB_XOR_PER_ROUND; xi++) {
            int step = xi % 3;
            int col = xi / 3;

            for (int src = 0; src < NB_XOR_BITS; src++) {
                int dst = src;
                int out_bit_index = src;
                const uint8_t *mask_a_ptr;
                const uint8_t *mask_b_ptr;

                /* Node 0: rows 0+1; Node 1: rows 2+3; Node 2: root combining Node 0 + Node 1 */
                if (step == 0) {
                    mask_a_ptr = M_CTY[r][0];
                    mask_b_ptr = M_CTY[r][1];
                } else if (step == 1) {
                    mask_a_ptr = M_CTY[r][2];
                    mask_b_ptr = M_CTY[r][3];
                } else {
                    int base = xi - 2;
                    mask_a_ptr = M_XOR[r][base];
                    mask_b_ptr = M_XOR[r][base + 1];
                    /* Invert mixing bijection at root to restore original bit positions */
                    dst = MIX_POS[r][col][src];
                    out_bit_index = dst;
                }

                uint8_t mask_a = get_mask_bit(mask_a_ptr, src);
                uint8_t mask_b = get_mask_bit(mask_b_ptr, src);
                uint8_t mask_out = get_mask_bit(M_XOR[r][xi], out_bit_index);
                uint8_t delta = mask_a ^ mask_b ^ mask_out;

                for (int a = 0; a < 2; a++) {
                    for (int b = 0; b < 2; b++) {
                        uint8_t out_bit = (uint8_t)(a ^ b ^ delta);
                        XOR_BIT_TABLES[r][xi][src][a][b] = out_bit ? (1U << (31 - dst)) : 0U;
                    }
                }
            }
        }
    }
}

/* Exports precomputed white-box tables into C header file */
static void generate_header(FILE *wb_header) {
    fprintf(wb_header,
        "#pragma once\n\n"
        "#include <stdint.h>\n\n"
        "#define NB_ROUNDS      %d\n"
        "#define KEY_SIZE       %d\n"
        "#define STATE_NB_ROW   %d\n"
        "#define NB_XOR_NIBBLES %d\n"
        "#define NB_XOR_BITS    %d\n\n",
        NB_ROUNDS, KEY_SIZE, STATE_NB_ROW, NB_XOR_NIBBLES, NB_XOR_BITS);

    /* FINAL_T_BOX */
    fprintf(wb_header, "static const uint8_t FINAL_T_BOX[%d][%d] = {\n", KEY_SIZE, ALL_BYTES_FOR_KEY);
    for (int i = 0; i < KEY_SIZE; i++) {
        fprintf(wb_header, "\t{");
        for (int x = 0; x < ALL_BYTES_FOR_KEY; x++) {
            fprintf(wb_header, "0x%02X%s", FINAL_T_BOX[i][x], COMMA_IF(x + 1 < ALL_BYTES_FOR_KEY));
        }
        fprintf(wb_header, "}%s\n", COMMA_IF(i + 1 < KEY_SIZE));
    }
    fprintf(wb_header, "};\n\n");

    /* CTY_TABLES */
    fprintf(wb_header, "static const uint32_t CTY_TABLES[%d][%d][%d][%d] = {\n",
            NB_ROUNDS - 1, STATE_NB_ROW, STATE_NB_ROW, ALL_BYTES_FOR_KEY);
    for (int r = 0; r < NB_ROUNDS - 1; r++) {
        fprintf(wb_header, "{\n");
        for (int y = 0; y < STATE_NB_ROW; y++) {
            fprintf(wb_header, "\t{\n");
            for (int c = 0; c < STATE_NB_ROW; c++) {
                fprintf(wb_header, "\t\t{");
                for (int x = 0; x < ALL_BYTES_FOR_KEY; x++) {
                    fprintf(wb_header, "0x%08X%s", CTY_TABLES[r][y][c][x], COMMA_IF(x + 1 < ALL_BYTES_FOR_KEY));
                }
                fprintf(wb_header, "}%s\n", COMMA_IF(c + 1 < STATE_NB_ROW));
            }
            fprintf(wb_header, "\t}%s\n", COMMA_IF(y + 1 < STATE_NB_ROW));
        }
        fprintf(wb_header, "}%s\n", COMMA_IF(r + 1 < NB_ROUNDS - 1));
    }
    fprintf(wb_header, "};\n\n");

    /* XOR_BIT_TABLES */
    fprintf(wb_header, "static const uint32_t XOR_BIT_TABLES[%d][%d][%d][2][2] = {\n",
            NB_ROUNDS - 1, NB_XOR_PER_ROUND, NB_XOR_BITS);
    for (int r = 0; r < NB_ROUNDS - 1; r++) {
        fprintf(wb_header, "{\n");
        for (int x = 0; x < NB_XOR_PER_ROUND; x++) {
            fprintf(wb_header, "\t{\n");
            for (int bit = 0; bit < NB_XOR_BITS; bit++) {
                fprintf(wb_header, "\t\t{\n");
                for (int a = 0; a < 2; a++) {
                    fprintf(wb_header, "\t\t\t{");
                    for (int b = 0; b < 2; b++) {
                        fprintf(wb_header, "0x%08X%s", XOR_BIT_TABLES[r][x][bit][a][b], COMMA_IF(b + 1 < 2));
                    }
                    fprintf(wb_header, "}%s\n", COMMA_IF(a + 1 < 2));
                }
                fprintf(wb_header, "\t\t}%s\n", COMMA_IF(bit + 1 < NB_XOR_BITS));
            }
            fprintf(wb_header, "\t}%s\n", COMMA_IF(x + 1 < NB_XOR_PER_ROUND));
        }
        fprintf(wb_header, "}%s\n", COMMA_IF(r + 1 < NB_ROUNDS - 1));
    }
    fprintf(wb_header, "};\n\n");
}

static void usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s <key:32-hex>\n"
                    "  <key:32-hex> must be exactly %d hexadecimal characters (0-9, a-f, A-F)\n",
            prog_name, KEY_SIZE * 2);
}

static void print_hex(const uint8_t *key, int length) {
    for (int i = 0; i < length; i++)
        printf("%02X", key[i]);
}

int main(int argc, char *argv[]) {
    if (argc < 2 || strlen(argv[1]) != KEY_SIZE * 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    uint8_t key[KEY_SIZE];
    for (int i = 0; i < KEY_SIZE; i++) {
        if (sscanf(&argv[1][i * 2], "%2hhx", &key[i]) != 1) {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    FILE *wb_header = fopen(WHITEBOX_HEADER, "w+");
    if (!wb_header)
        errx(EXIT_FAILURE, "error: file '%s' could not be opened\n", WHITEBOX_HEADER);

    init_masks();
    init_mix_bijections();

    uint8_t expanded_key[NB_ROUNDS + 1][KEY_SIZE];
    KeyExpansion(key, expanded_key);

    init_t_boxes(expanded_key);
    init_ty_tables();
    init_cty_tables();
    init_xor_tables();

    generate_header(wb_header);
    fclose(wb_header);

    printf("Generated whitebox header for key ");
    print_hex(key, KEY_SIZE);
    printf(" in file '%s'\n", WHITEBOX_HEADER);

    return EXIT_SUCCESS;
}