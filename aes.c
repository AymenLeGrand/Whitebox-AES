#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define INPUT_SIZE          16
#define KEY_LENGTH_W        4
#define KEY_SIZE            16
#define ALL_BYTES_FOR_KEY   (KEY_SIZE * KEY_SIZE)
#define STATE_NB_ROW        4
#define NB_ROUNDS           10
#define NB_XOR_PER_ROUND    12
#define NB_XOR_NIBBLES      8

/* Internal lookup tables for reference white-box execution */
static uint8_t TBoxes[NB_ROUNDS][KEY_SIZE][256];
static uint32_t TyBoxes[4][36][256];
static uint8_t XorTables[NB_ROUNDS - 1][12][8][16][16];
static uint32_t CTyBoxes[NB_ROUNDS - 1][STATE_NB_ROW][STATE_NB_ROW][KEY_SIZE][ALL_BYTES_FOR_KEY];

/* MixColumns MDS transformation matrix */
static const uint8_t MC[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};

/* Round constants for key expansion */
static const uint8_t Rcon[10][4] = {
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

/* AES Rijndael S-Box */
static const uint8_t SBox[256] = {
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

/* Evaluates 32-bit addition by combining 4-bit nibbles through XOR tables */
static inline uint32_t XOR32(uint32_t a, uint32_t b, int round, int xor_index) {
    uint32_t r = 0;

    for (int n = 0; n < 8; n++) {
        uint8_t na = (a >> (4 * (7 - n))) & 0xF;
        uint8_t nb = (b >> (4 * (7 - n))) & 0xF;

        uint8_t nr = XorTables[round][xor_index][n][na][nb];
        r |= ((uint32_t)nr) << (4 * (7 - n));
    }

    return r;
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

/* Standard AES-128 key schedule: expands 16-byte key into 11 round keys */
static void KeyExpansion(const uint8_t *key, uint8_t res[NB_ROUNDS + 1][KEY_SIZE]) {
    uint8_t w[(NB_ROUNDS + 1) * INPUT_SIZE];
    memcpy(w, key, INPUT_SIZE);

    int i = KEY_LENGTH_W;
    uint8_t temp[4];
    while (i <= ((4 * NB_ROUNDS) + 3)) {
        memcpy(temp, &w[(i - 1) * 4], 4);
        if (i % KEY_LENGTH_W == 0) {
            RotWord(temp);
            SubWord(temp);
            int rcon_index = (i / KEY_LENGTH_W) - 1;

            for (int j = 0; j < 4; j++)
                temp[j] ^= Rcon[rcon_index][j];
        } else if ((KEY_LENGTH_W > 6) && (i % KEY_LENGTH_W == 4)) {
            SubWord(temp);
        }

        for (int j = 0; j < 4; j++)
            w[i * 4 + j] = w[(i - KEY_LENGTH_W) * 4 + j] ^ temp[j];

        i++;
    }

    for (int r = 0; r < NB_ROUNDS + 1; r++) {
        for (int j = 0; j < INPUT_SIZE; j++)
            res[r][j] = w[r * INPUT_SIZE + j];
    }
}

/* Cyclic row shift on 4x4 state matrix */
static void ShiftRows(uint8_t *state) {
    uint8_t state_copy[INPUT_SIZE];
    memcpy(state_copy, state, INPUT_SIZE);
    for (int i = 0; i < INPUT_SIZE; i++)
        state[i] = state_copy[(i * 5) % INPUT_SIZE];
}

/* Galois Field GF(2^8) multiplication modulo irreducible polynomial x^8 + x^4 + x^3 + x + 1 */
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

/* Multiplies a byte by the b-th column vector of the MixColumns matrix */
static uint32_t MatrixMult(int b, uint8_t x) {
    uint32_t res = 0;
    uint8_t temp[4] = {0};
    for (int i = 0; i < 4; i++)
        temp[i] = MultGF128(x, MC[i][b]);

    for (int i = 0; i < 4; i++)
        res |= (uint32_t)temp[i] << (24 - (i * 8));

    return res;
}

static void print_hex(const uint8_t *data, int length) {
    for (int i = 0; i < length; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % INPUT_SIZE == 0)
            printf("\n");
    }
}

/* Precomputes T-boxes fusing AddRoundKey with S-Box */
static void InitTBoxes(uint8_t keys[NB_ROUNDS + 1][INPUT_SIZE]) {
    uint8_t shifted_key[INPUT_SIZE];

    for (int r = 1; r <= NB_ROUNDS - 1; r++) {
        memcpy(shifted_key, keys[r - 1], INPUT_SIZE);
        ShiftRows(shifted_key);

        for (int i = 0; i < INPUT_SIZE; i++) {
            for (int x = 0; x < 256; x++)
                TBoxes[r - 1][i][x] = SBox[x ^ shifted_key[i]];
        }
    }

    /* Final round merges round 9 key and final round 10 key (no MixColumns in round 10) */
    memcpy(shifted_key, keys[NB_ROUNDS - 1], 16);
    ShiftRows(shifted_key);

    for (int i = 0; i < INPUT_SIZE; i++) {
        for (int x = 0; x < 256; x++)
            TBoxes[NB_ROUNDS - 1][i][x] = SBox[x ^ shifted_key[i]] ^ keys[NB_ROUNDS][i];
    }
}

/* Precomputes MixColumns multiplication lookups */
static void InitTy(void) {
    for (int ty = 0; ty < 4; ty++) {
        for (int copy = 0; copy < 36; copy++) {
            for (int x = 0; x < 256; x++)
                TyBoxes[ty][copy][x] = MatrixMult(ty, x);
        }
    }
}

/* Precomputes nibble-level XOR tables */
static void Generate_XOR_Tables(void) {
    for (int r = 0; r < NB_ROUNDS - 1; r++) {
        for (int xi = 0; xi < 12; xi++) {
            for (int n = 0; n < 8; n++) {
                for (int x = 0; x < 16; x++) {
                    for (int y = 0; y < 16; y++)
                        XorTables[r][xi][n][x][y] = x ^ y;
                }
            }
        }
    }
}

/* Composes T-box lookups with Ty matrix multiplication (CTY = Ty o T) */
static void Generate_Composed_TY(void) {
    for (int r = 0; r < NB_ROUNDS - 1; r++) {
        for (int y = 0; y < 4; y++) {
            for (int c = 0; c < 4; c++) {
                int ty_index = r * 4 + c;

                for (int i = 0; i < KEY_SIZE; i++) {
                    for (int x = 0; x < 256; x++) {
                        uint8_t t = TBoxes[r][i][x];
                        CTyBoxes[r][y][c][i][x] = TyBoxes[y][ty_index][t];
                    }
                }
            }
        }
    }
}

/* Reference White-Box AES encryption loop */
static void AES_128_WB(uint8_t *state) {
    /* Rounds 1 to 9: ShiftRows, 4 CTY lookups per column, and 3-node XOR addition */
    for (int r = 0; r < 9; r++) {
        ShiftRows(state);
        uint8_t new_state[16];
        for (int c = 0; c < 4; c++) {
            uint32_t acc = 0;

            uint32_t v0 = CTyBoxes[r][0][c][c * 4 + 0][state[c * 4 + 0]];
            uint32_t v1 = CTyBoxes[r][1][c][c * 4 + 1][state[c * 4 + 1]];
            uint32_t v2 = CTyBoxes[r][2][c][c * 4 + 2][state[c * 4 + 2]];
            uint32_t v3 = CTyBoxes[r][3][c][c * 4 + 3][state[c * 4 + 3]];

            acc = XOR32(acc, v0, r, 0);
            acc = XOR32(acc, v1, r, 1);
            acc = XOR32(acc, v2, r, 2);
            acc = XOR32(acc, v3, r, 3);

            new_state[c * 4 + 0] = (acc >> 24) & 0xff;
            new_state[c * 4 + 1] = (acc >> 16) & 0xff;
            new_state[c * 4 + 2] = (acc >> 8) & 0xff;
            new_state[c * 4 + 3] = acc & 0xff;
        }
        memcpy(state, new_state, 16);
        printf("round[%d].n_col\t", r + 1);
        print_hex(state, INPUT_SIZE);
    }

    /* Round 10: ShiftRows and final T-box lookup */
    ShiftRows(state);
    for (int i = 0; i < INPUT_SIZE; i++)
        state[i] = TBoxes[9][i][state[i]];
}

int main(int argc, char *argv[]) {
    if (argc < 3 || strlen(argv[1]) != KEY_SIZE * 2 || strlen(argv[2]) != INPUT_SIZE * 2) {
        fprintf(stderr, "Usage: %s <key:32-hex> <plaintext:32-hex>\n", argv[0]);
        return EXIT_FAILURE;
    }

    uint8_t key[INPUT_SIZE];
    uint8_t input[INPUT_SIZE];
    for (int i = 0; i < INPUT_SIZE; i++) {
        sscanf(&argv[1][i * 2], "%2hhx", &key[i]);
        sscanf(&argv[2][i * 2], "%2hhx", &input[i]);
    }

    uint8_t expanded_key[NB_ROUNDS + 1][INPUT_SIZE];
    KeyExpansion(key, expanded_key);

    printf("Original key:\t");
    print_hex(key, INPUT_SIZE);
    printf("Original input:\t");
    print_hex(input, INPUT_SIZE);

    printf("Expanded key:\n");
    for (int r = 0; r < NB_ROUNDS + 1; r++)
        print_hex(expanded_key[r], INPUT_SIZE);

    InitTBoxes(expanded_key);
    InitTy();
    Generate_Composed_TY();
    Generate_XOR_Tables();

    AES_128_WB(input);

    printf("Encoded input:\t");
    print_hex(input, INPUT_SIZE);
    return EXIT_SUCCESS;
}
