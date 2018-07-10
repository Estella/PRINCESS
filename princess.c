/*******************************************************************************************************/
// PRINCESS v 0.0.110
/*******************************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <limits.h>
#include <inttypes.h>
#include <string.h>

#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>
#include <assert.h>
#include <errno.h>
/*******************************************************************************************************/
#include "csbox.h"
/*******************************************************************************************************/
#define DEBUG_META 0
#define DEBUG_PRNG 0
#define DEBUG_HEAD 0
#define DEBUG_SBOX 0
#define DEBUG_KEYS 0
/*******************************************************************************************************/
#define PRINCESS_BLOCKLEN 16
#define PRINCESS_keyExpSize 240
#define Nb 4
#define Nk 8
#define Nr 14
/*******************************************************************************************************/
struct PRINCESS_ctx {
  uint8_t RoundKey[PRINCESS_keyExpSize];
  uint8_t IV_X[2 * PRINCESS_BLOCKLEN];
  uint8_t IV_Y[2 * PRINCESS_BLOCKLEN];
  int mode;
};
/*******************************************************************************************************/
typedef uint8_t state_t[4][4];
/*******************************************************************************************************/
uint8_t p_sbox[256]; uint8_t f_sbox[256]; uint8_t i_sbox[256];
/*******************************************************************************************************/
uint8_t scube_f[256][256];
uint8_t scube_i[256][256];
/*******************************************************************************************************/
uint64_t PRNG_CNT = 0;
uint64_t CSPRNG_CNT = 0;
/*******************************************************************************************************/
void dumpcounters();
size_t blocks(FILE *fp);
unsigned char lastblock(FILE *fp);
void dump_entropy(uint8_t *data,int len);
uint64_t IVCSPRNG(void);
uint64_t CSPRNG(void);
void dump_keys(struct PRINCESS_ctx* ctx);
void dump_header(uint8_t* header);
void PRINCESS_init_preboot(struct PRINCESS_ctx* ctx, const uint8_t* password, int passlen, int mode);
uint8_t ENBOX(uint8_t input, uint8_t loop);
uint64_t ENHASH(uint64_t input, uint64_t loop);
void PRINCESS_MYST_decrypt_buffer(struct PRINCESS_ctx* ctx, uint8_t* buf, uint32_t length);
void PRINCESS_MYST_encrypt_buffer(struct PRINCESS_ctx* ctx, uint8_t* buf, uint32_t length);
void HeadCrypt(uint8_t* header);
void BlockCrypt(uint8_t* block, int mode);
void RedCrypt(uint8_t *block, int mode);
static void MutateBy(uint8_t* AA, uint8_t* BB, int mode);
static void InvCipher(state_t* state,uint8_t* RoundKey);
static void Cipher(state_t* state, uint8_t* RoundKey);
static void InvShiftRows(state_t* state);
static void InvSubBytes(state_t* state);
static void InvMixColumns(state_t* state);
static uint8_t Multiply(uint8_t x, uint8_t y);
static void MixColumns(state_t* state);
static void ShiftRows(state_t* state);
static void InvMetaBytes(uint8_t round, state_t* state,uint8_t* RoundKey);
static void MetaBytes(uint8_t round, state_t* state,uint8_t* RoundKey);
static void InvCubeBytes(uint8_t round, state_t* state, uint8_t* RoundKey);
static void CubeBytes(uint8_t round, state_t* state, uint8_t* RoundKey);
static void SubBytes(state_t* state);
static void AddCubeKey(uint8_t round,state_t* state,uint8_t* RoundKey);
static void AddRoundKey(uint8_t round,state_t* state,uint8_t* RoundKey);
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key);
void shuffle(uint8_t sbox[256]);
void ashuffle(uint32_t sbox[256]);
void gen_ibox(uint8_t sbox[256], uint8_t ibox[256]);
void print_sbox(uint8_t sbox[256]);
void print_qbox(uint32_t sbox[256]);
void gen_sbox(uint8_t byte, uint8_t sbox[256]);
uint8_t MetaCLU(uint8_t AA, uint8_t BB, int MODE);
uint32_t MetaCLU32(uint32_t AA, uint32_t BB, int MODE);
char *int2bin(unsigned n, char *buf);
void print_hex(uint8_t* str, uint64_t len);
static void const *sha3_Finalize(void *priv);
static void sha3_Update(void *priv, void const *bufIn, size_t len);
static void sha3_Init256(void *priv);
static void keccakf(uint64_t s[25]);
void PRNG_BOOT(uint64_t *seed);
uint16_t JUMPSKIP(uint64_t JUMP);
uint64_t CONSTANT_META_3D(uint64_t x);
uint64_t CONSTANT_META(uint64_t x);
uint64_t PRNG(void);
uint64_t XS(void);
uint64_t CNG(void);
uint64_t B64MWC(void);
uint32_t XBOX_MUTATE_2D(uint32_t m, uint32_t x);
uint32_t XBOX_MUTATE_3D(uint32_t m, uint32_t x);
uint64_t IVPRNG(void);
uint64_t REDPRNG(void);
uint64_t BLUEPRNG1(void);
uint64_t BLUEPRNG2(void);
static inline uint64_t irotl64(const uint64_t x, int k);
uint64_t META_MIX_3D(uint64_t x);
static void meta_mix(uint64_t x[4]);
/*******************************************************************************************************/
uint64_t XS_IV_s[2];
static uint64_t RED_S1[2];
/*******************************************************************************************************/
static uint64_t BLUE_s1[2];
static uint64_t BLUE_s2[2];
/*******************************************************************************************************/
static inline uint64_t irotl64(const uint64_t x, int k) {
  return (x << k) | (x >> (64 - k));
}
/*******************************************************************************************************/
uint64_t IVPRNG(void) { // xorshift128plus
  uint64_t x = XS_IV_s[0];
  uint64_t const y = XS_IV_s[1];
  XS_IV_s[0] = y;
  x ^= x << 23;
  XS_IV_s[1] = x ^ y ^ (x >> 17) ^ (y >> 26);
  return META_MIX_3D(XS_IV_s[1] + y);
}
/*******************************************************************************************************/
uint64_t REDPRNG(void) { // xorshift128starstar
  const uint64_t s0 = RED_S1[0];
  uint64_t s1 = RED_S1[1];
  const uint64_t result = irotl64(s0 * 5, 7) * 9;
  s1 ^= s0;
  RED_S1[0] = irotl64(s0, 24) ^ s1 ^ (s1 << 16); // a, b
  RED_S1[1] = irotl64(s1, 37); // c
  return META_MIX_3D(result);
}
/*******************************************************************************************************/
uint64_t BLUEPRNG1(void) { // xorshift128starstar
  const uint64_t s0 = BLUE_s1[0];
  uint64_t s1 = BLUE_s1[1];
  const uint64_t result = irotl64(s0 * 5, 7) * 9;
  s1 ^= s0;
  BLUE_s1[0] = irotl64(s0, 24) ^ s1 ^ (s1 << 16); // a, b
  BLUE_s1[1] = irotl64(s1, 37); // c
  return META_MIX_3D(result);
}
/*******************************************************************************************************/
uint64_t BLUEPRNG2(void) { // xorshift128starstar
  const uint64_t s0 = BLUE_s2[0];
  uint64_t s1 = BLUE_s2[1];
  const uint64_t result = irotl64(s0 * 5, 7) * 9;
  s1 ^= s0;
  BLUE_s2[0] = irotl64(s0, 24) ^ s1 ^ (s1 << 16); // a, b
  BLUE_s2[1] = irotl64(s1, 37); // c
  return META_MIX_3D(result);
}
/*******************************************************************************************************/
#define S64BYTES(x, y) \
      ((y)[0] = (unsigned char)(((x) >> 56) & 0xFF), (y)[1] = (unsigned char)(((x) >> 48) & 0xFF), \
       (y)[2] = (unsigned char)(((x) >> 40) & 0xFF), (y)[3] = (unsigned char)(((x) >> 32) & 0xFF), \
       (y)[4] = (unsigned char)(((x) >> 24) & 0xFF), (y)[5] = (unsigned char)(((x) >> 16) & 0xFF), \
       (y)[6] = (unsigned char)(((x) >>  8) & 0xFF), (y)[7] = (unsigned char)((x)         & 0xFF))
/*******************************************************************************************************/
#define L64BYTES(x, y) \
      (x = (((uint64_t)((y)[0] & 0xFF)) << 56) | (((uint64_t)((y)[1] & 0xFF)) << 48) | \
           (((uint64_t)((y)[2] & 0xFF)) << 40) | (((uint64_t)((y)[3] & 0xFF)) << 32) | \
           (((uint64_t)((y)[4] & 0xFF)) << 24) | (((uint64_t)((y)[5] & 0xFF)) << 16) | \
           (((uint64_t)((y)[6] & 0xFF)) <<  8) | (((uint64_t)((y)[7] & 0xFF))))
/*******************************************************************************************************/
#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))
#define ROTR8(x,shift) ((uint8_t) ((x) >> (shift)) | ((x) << (8 - (shift))))
/*******************************************************************************************************/
// csbox[11][4][256] // [0] Euler Constant, [1] Catalan G, [2] Gamma(1_4), [3] Lemniscate, [4] Log(10), [5] Log(2), [6] PI, [7] E, [8] PHI, [9] SQRT(3), [10] SQRT(2)
#define CSLEN 11
/*******************************************************************************************************/
#define XBOX_2D(x,t) ( \
  (t  = csbox[((p_sbox[(((x) >> 24) & 0xFF)]) % CSLEN)][0][(((x) >> 24) & 0xFF)]), \
  (t += csbox[((p_sbox[(((x) >> 16) & 0xFF)]) % CSLEN)][1][(((x) >> 16) & 0xFF)]), \
  (t ^= csbox[((p_sbox[(((x) >> 8) & 0xFF)]) % CSLEN)][2][(((x) >> 8) & 0xFF)]), \
  (t += csbox[((p_sbox[((x) & 0xFF)]) % CSLEN)][3][((x) & 0xFF)]))
/*******************************************************************************************************/
#define XBOX_3D(x,t) ( \
  (t  = csbox[((f_sbox[scube_f[(((x) >> 24) & 0xFF) ][((x) & 0xFF)]]) % CSLEN)][0][(((x) >> 24) & 0xFF)]), \
  (t += csbox[((f_sbox[scube_f[(((x) >> 16) & 0xFF) ][(((x) >> 8) & 0xFF)]]) % CSLEN)][1][(((x) >> 16) & 0xFF)]), \
  (t ^= csbox[((f_sbox[scube_f[(((x) >> 8) & 0xFF) ][(((x) >> 16) & 0xFF)]]) % CSLEN)][2][(((x) >> 8) & 0xFF)]), \
  (t += csbox[((f_sbox[scube_f[((x) & 0xFF) ][(((x) >> 24) & 0xFF)]]) % CSLEN)][3][((x) & 0xFF)]))
/*******************************************************************************************************/
uint32_t XBOX_MUTATE_2D(uint32_t m, uint32_t x) { uint32_t o = x; XBOX_2D(m,o); return (o & 0xFFFFFFFF); }
uint32_t XBOX_MUTATE_3D(uint32_t m, uint32_t x) { uint32_t o = x; XBOX_3D(m,o); return (o & 0xFFFFFFFF); }
/*******************************************************************************************************/
static const uint8_t Rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };
/*******************************************************************************************************/
//static uint32_t rx,ry,rz,rw,rv,rd;
/*******************************************************************************************************/
#define w 8
#define ROL(x,y) (((x)<<(y&(w-1))) | ((x)>>(w-(y&(w-1)))))
#define ROR(x,y) (((x)>>(y&(w-1))) | ((x)<<(w-(y&(w-1)))))
#define XOR(x,y) (x^y)
#define NOP(x) (x)
#define INV(x) (~x)
/*******************************************************************************************************/
#define ROL32(X, R) (((X) << ((R) & 31)) | ((X) >> (32 - ((R) & 31))))
#define ROR32(X, R) (((X) >> ((R) & 31)) | ((X) << (32 - ((R) & 31))))
#define XOR32(x,y) (x^y)
#define NOP32(x) (x)
#define INV32(x) (~x)
#define END32(x) ( ( x >> 24 ) | (( x << 8) & 0x00ff0000 ) | ((x >> 8) & 0x0000ff00) | ( x << 24) )
/*******************************************************************************************************/
#define END64(x) ( x = (x & 0x00000000FFFFFFFF) << 32 | (x & 0xFFFFFFFF00000000) >> 32, x = (x & 0x0000FFFF0000FFFF) << 16 | (x & 0xFFFF0000FFFF0000) >> 16, x = (x & 0x00FF00FF00FF00FF) << 8 | (x & 0xFF00FF00FF00FF00) >> 8 )
/*******************************************************************************************************/
#define ROTL64(a,b) (((a)<<(b))|((a)>>(64-b)))
/*******************************************************************************************************/
static void meta_mix(uint64_t x[4]) {
  x[0] += CONSTANT_META_3D(x[1]);
  x[2] += CONSTANT_META_3D(x[3]);
  x[1] = CONSTANT_META_3D(ROTL64(x[1],13) ^ x[0]);
  x[3] = CONSTANT_META_3D(ROTL64(x[3],16) ^ x[2]);
  x[0] = CONSTANT_META_3D(ROTL64(x[0],32));
  x[2] += CONSTANT_META_3D(x[1]);
  x[0] += CONSTANT_META_3D(x[3]);
  x[1] = CONSTANT_META_3D(ROTL64(x[1],17) ^ x[2]);
  x[3] = CONSTANT_META_3D(ROTL64(x[3],21) ^ x[0]);
  x[2] = CONSTANT_META_3D(ROTL64(x[2],32));
}
/*******************************************************************************************************/
uint64_t META_MIX_3D(uint64_t x) {
  uint64_t y[4];
  y[0] = CONSTANT_META(x);
  y[1] = CONSTANT_META_3D(x);
  y[2] = x;
  y[3] = CONSTANT_META_3D(y[0] ^ y[1]);
  meta_mix(y);

  y[0] ^= CONSTANT_META_3D(y[3]);
  y[1] ^= CONSTANT_META_3D(y[2]);
  y[2] ^= CONSTANT_META_3D(y[1]);
  y[3] ^= CONSTANT_META_3D(y[0]);

  y[0] ^= CONSTANT_META(END64(y[3]));
  y[1] ^= CONSTANT_META(END64(y[2]));
  y[2] ^= CONSTANT_META(END64(y[1]));
  y[3] ^= CONSTANT_META(END64(y[0]));

  return ((y[0] ^ y[1]) ^ (y[2] ^ y[3]));
}
/*******************************************************************************************************/
#define QSIZE 2097152
uint64_t Q[QSIZE];
uint64_t prng_carry = 0x0000000000000000;
uint64_t prng_cng   = 0x0000000000000000;
uint64_t prng_xs    = 0x0000000000000000;
uint64_t prng_pos   = 0x0000000000000000;
/*******************************************************************************************************/
uint64_t B64MWC(void) {
  uint64_t bt,bx;
  prng_pos = (prng_pos + 1) & (QSIZE - 1);
  bx = Q[prng_pos]; bt = (bx << 28) + prng_carry;
  prng_carry = (bx >> 36) - (bt < bx);
  return (Q[prng_pos] = bt - bx);
}
/*******************************************************************************************************/
uint64_t CNG(void) { return (prng_cng = 6906969069LL * prng_cng + 13579); } // LCG 64bit
/*******************************************************************************************************/
uint64_t XS(void) { return ((prng_xs ^= (prng_xs << 13), prng_xs ^= (prng_xs >> 17), prng_xs ^= (prng_xs << 43))); } //XORSHIFT64 
/*******************************************************************************************************/
uint64_t PRNG(void) { PRNG_CNT++; return (B64MWC()+CNG()+XS()); }
/*******************************************************************************************************/
uint64_t CONSTANT_META(uint64_t x) {
  uint64_t o;
  uint32_t a,b;
  a = XBOX_MUTATE_2D((x >> 32),(x & 0xFFFFFFFF));
  b = XBOX_MUTATE_2D((x & 0xFFFFFFFF),(x >> 32));
  o = ((uint64_t)a << 32) | (uint64_t)b;
  return o;
}
/*******************************************************************************************************/
uint64_t CONSTANT_META_3D(uint64_t x) {
  uint64_t o;
  uint32_t a,b;
  a = XBOX_MUTATE_3D((x >> 32),(x & 0xFFFFFFFF));
  b = XBOX_MUTATE_3D((x & 0xFFFFFFFF),(x >> 32));
  o = ((uint64_t)a << 32) | (uint64_t)b;
  //printf("CONSTANT_META (64bit): %016llX\n", o);
  return o;
}
/*******************************************************************************************************/
uint16_t JUMPSKIP(uint64_t JUMP) {
  uint64_t L1,R1,L2,R2;
  uint32_t JUMPSEED[2];
  uint32_t JUMPSKIP;
  uint8_t a,b,c,d;
  uint16_t x;
  JUMPSEED[0] = (JUMP >> 32); 
  JUMPSEED[1] = (JUMP & 0xFFFFFFFF);
  L1 = JUMPSEED[0]; XBOX_2D(L1,R1);
  L2 = JUMPSEED[1]; XBOX_2D(L2,R2);
  JUMPSKIP = (R1 ^ R2);
  a = (JUMPSKIP & 0x000000ff);
  b = (JUMPSKIP & 0x0000ff00) >> 8;
  c = (JUMPSKIP & 0x00ff0000) >> 16;
  d = (JUMPSKIP & 0xff000000) >> 24;
  x = ((uint16_t)(a^b) << 8) | (c^d);
  return x;
}
/*******************************************************************************************************/
void PRNG_BOOT(uint64_t *seed) {
  uint64_t JUMP = 0x0000000000000000;
  prng_carry = 0x0000000000000000;
  prng_cng   = 0x01B69B4BE052FAB1;
  prng_xs = 0x0507A1AF502307E5;
  prng_pos = (QSIZE - 1);  
  int i;  
  Q[0] = seed[0];
  Q[1] = seed[1] + CONSTANT_META(Q[0]);
  Q[2] = seed[2] + CONSTANT_META(Q[0]) + CONSTANT_META(Q[1]);
  Q[3] = seed[3] + CONSTANT_META(Q[0]) + CONSTANT_META(Q[1]) + CONSTANT_META(Q[2]);
  Q[4] = seed[4] + CONSTANT_META(Q[0]) + CONSTANT_META(Q[1]) + CONSTANT_META(Q[2]) + CONSTANT_META(Q[3]);
  Q[5] = seed[5] + CONSTANT_META(Q[0]) + CONSTANT_META(Q[1]) + CONSTANT_META(Q[2]) + CONSTANT_META(Q[3]) + CONSTANT_META(Q[4]);
  Q[6] = seed[6] + CONSTANT_META(Q[0]) + CONSTANT_META(Q[1]) + CONSTANT_META(Q[2]) + CONSTANT_META(Q[3]) + CONSTANT_META(Q[4]) + CONSTANT_META(Q[5]);
  Q[7] = seed[7] + CONSTANT_META(Q[0]) + CONSTANT_META(Q[1]) + CONSTANT_META(Q[2]) + CONSTANT_META(Q[3]) + CONSTANT_META(Q[4]) + CONSTANT_META(Q[5]) + CONSTANT_META(Q[6]);
  for (i = 8; i < QSIZE; i++) {
    Q[i] = Q[i - 7] ^ Q[i - 6] ^ Q[i - 5] ^ Q[i - 4] ^ Q[i - 3] ^ Q[i - 2];
    int meta = (Q[i] % 4);
    switch(meta) {
      case 0:
        Q[i] += CONSTANT_META(Q[i]);
        break;
      case 1:
        Q[i] ^= CONSTANT_META(Q[i]);
        break;
      case 2:
        Q[i] -= CONSTANT_META(Q[i]);
        break;
      case 3:
        break;
    }
    JUMP ^= (uint64_t)Q[i];
  }

  prng_carry ^= JUMP; prng_cng ^= JUMP; prng_xs ^= JUMP;
  prng_carry ^= CONSTANT_META((prng_carry ^ CONSTANT_META(seed[(prng_carry % 8)])));
  prng_cng   ^= CONSTANT_META((prng_cng   ^ CONSTANT_META(seed[(prng_cng   % 8)])));
  prng_xs    ^= CONSTANT_META((prng_xs    ^ CONSTANT_META(seed[(prng_xs    % 8)])));

  int JUMPLEN = (1024 + (int)JUMPSKIP(JUMP));
  int CARRYLEN = (1024 + (int)JUMPSKIP(prng_carry));
  int CNGLEN = (1024 + (int)JUMPSKIP(prng_cng));
  int XSLEN = (1024 + (int)JUMPSKIP(prng_xs));

  for (i = 0; i < CARRYLEN; i++) { prng_carry ^= CONSTANT_META((prng_carry ^ CONSTANT_META(seed[(prng_carry % 8)]))); }
  for (i = 0; i < CNGLEN; i++) {   prng_cng   ^= CONSTANT_META((prng_cng   ^ CONSTANT_META(seed[(prng_cng   % 8)]))); }
  for (i = 0; i < XSLEN; i++) {    prng_xs    ^= CONSTANT_META((prng_xs    ^ CONSTANT_META(seed[(prng_xs    % 8)]))); }

  int CARRY2LEN = (1024 + (int)JUMPSKIP(prng_carry));
  int CNG2LEN = (1024 + (int)JUMPSKIP(prng_cng));
  int XS2LEN = (1024 + (int)JUMPSKIP(prng_xs));  

  for (i = 0; i < CARRY2LEN; i++) { B64MWC(); }
  for (i = 0; i < CNG2LEN; i++) { CNG(); }
  for (i = 0; i < XS2LEN; i++) {  XS(); }
  for (i = 0; i < JUMPLEN; i++) { PRNG(); }
  if (DEBUG_PRNG) {
    printf("PRNG OFFSETS: CARRY = %d, B64MWC = %d, CNG = %d (%d), XS = %d (%d), PRNG = %d\n\n\n",CARRYLEN,CARRY2LEN,CNGLEN,CNG2LEN,XSLEN,XS2LEN,JUMPLEN);
    printf("PRNG CARRY (64bit): %016llX\n", prng_carry);  
    printf("PRNG CNG (64bit): %016llX\n", prng_cng);    
    printf("PRNG XS (64bit): %016llX\n", prng_xs);   
  }
}
/*******************************************************************************************************/
#define KECCAK_ROUNDS 24
/*******************************************************************************************************/
#define SHA3_ASSERT( x )
#define SHA3_CONST(x) x##L
/*******************************************************************************************************/
#define SHA3_KECCAK_SPONGE_WORDS (((1600)/8)/sizeof(uint64_t)) // 200 Bytes
#define SHA3_ROTL64(x, y) (((x) << (y)) | ((x) >> ((sizeof(uint64_t)*8) - (y))))
/*******************************************************************************************************/
typedef struct sha3_context_ {
  uint64_t saved;
  union {        
    uint64_t s[SHA3_KECCAK_SPONGE_WORDS];
    uint8_t sb[SHA3_KECCAK_SPONGE_WORDS * 8];
  };
  unsigned byteIndex;
  unsigned wordIndex;
  unsigned capacityWords;
} sha3_context;
/*******************************************************************************************************/
static const uint64_t keccakf_rndc[24] = {
  SHA3_CONST(0x0000000000000001UL), SHA3_CONST(0x0000000000008082UL),
  SHA3_CONST(0x800000000000808aUL), SHA3_CONST(0x8000000080008000UL),
  SHA3_CONST(0x000000000000808bUL), SHA3_CONST(0x0000000080000001UL),
  SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008009UL),
  SHA3_CONST(0x000000000000008aUL), SHA3_CONST(0x0000000000000088UL),
  SHA3_CONST(0x0000000080008009UL), SHA3_CONST(0x000000008000000aUL),
  SHA3_CONST(0x000000008000808bUL), SHA3_CONST(0x800000000000008bUL),
  SHA3_CONST(0x8000000000008089UL), SHA3_CONST(0x8000000000008003UL),
  SHA3_CONST(0x8000000000008002UL), SHA3_CONST(0x8000000000000080UL),
  SHA3_CONST(0x000000000000800aUL), SHA3_CONST(0x800000008000000aUL),
  SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008080UL),
  SHA3_CONST(0x0000000080000001UL), SHA3_CONST(0x8000000080008008UL)
};
/*******************************************************************************************************/
static const unsigned keccakf_rotc[24] = { 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44 };
static const unsigned keccakf_piln[24] = { 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1 };
/*******************************************************************************************************/
static void keccakf(uint64_t s[25]) {
  int i, j, round;
  uint64_t t, bc[5];
  for(round = 0; round < KECCAK_ROUNDS; round++) {
    /* Theta */
    for(i = 0; i < 5; i++) {
      bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
    }
    for(i = 0; i < 5; i++) {
      t = bc[(i + 4) % 5] ^ SHA3_ROTL64(bc[(i + 1) % 5], 1);
      for(j = 0; j < 25; j += 5) {
        s[j + i] ^= t;
      }
    }
    /* Rho Pi */
    t = s[1];
    for(i = 0; i < 24; i++) {
      j = keccakf_piln[i];
      bc[0] = s[j];
      s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
      t = bc[0];
    }
    /* Chi */
    for(j = 0; j < 25; j += 5) {
      for(i = 0; i < 5; i++) {
        bc[i] = s[j + i];
      }
      for(i = 0; i < 5; i++) {
        s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
      }
    }
    /* Iota */
    s[0] ^= keccakf_rndc[round];
  }
}
/*******************************************************************************************************/
static void sha3_Init256(void *priv) {
  sha3_context *ctx = (sha3_context *) priv;
  memset(ctx, 0, sizeof(*ctx));
  ctx->capacityWords = 2 * 256 / (8 * sizeof(uint64_t));
}
/*******************************************************************************************************/
static void sha3_Update(void *priv, void const *bufIn, size_t len) {
  sha3_context *ctx = (sha3_context *) priv;
  unsigned old_tail = (8 - ctx->byteIndex) & 7;
  size_t words;
  unsigned tail;
  size_t i;
  const uint8_t *buf = bufIn;
  SHA3_ASSERT(ctx->byteIndex < 8);
  SHA3_ASSERT(ctx->wordIndex < sizeof(ctx->s) / sizeof(ctx->s[0]));
  if (len < old_tail) {
    while (len--) {
      ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
    }
    SHA3_ASSERT(ctx->byteIndex < 8);
    return;
  }
  if(old_tail) {
    len -= old_tail;
    while (old_tail--) {
      ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
    }
    ctx->s[ctx->wordIndex] ^= ctx->saved;
    SHA3_ASSERT(ctx->byteIndex == 8);
    ctx->byteIndex = 0;
    ctx->saved = 0;
    if(++ctx->wordIndex == (SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords)) {
      keccakf(ctx->s);
      ctx->wordIndex = 0;
    }
  }
  SHA3_ASSERT(ctx->byteIndex == 0);
  words = len / sizeof(uint64_t);
  tail = len - words * sizeof(uint64_t);
  for(i = 0; i < words; i++, buf += sizeof(uint64_t)) {
    const uint64_t t = (uint64_t) (buf[0]) |
            ((uint64_t) (buf[1]) << 8 * 1) |
            ((uint64_t) (buf[2]) << 8 * 2) |
            ((uint64_t) (buf[3]) << 8 * 3) |
            ((uint64_t) (buf[4]) << 8 * 4) |
            ((uint64_t) (buf[5]) << 8 * 5) |
            ((uint64_t) (buf[6]) << 8 * 6) |
            ((uint64_t) (buf[7]) << 8 * 7);
    SHA3_ASSERT(memcmp(&t, buf, 8) == 0);
    ctx->s[ctx->wordIndex] ^= t;
    if(++ctx->wordIndex == (SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords)) {
      keccakf(ctx->s);
      ctx->wordIndex = 0;
    }
  }
  SHA3_ASSERT(ctx->byteIndex == 0 && tail < 8);
  while (tail--) {
    ctx->saved |= (uint64_t) (*(buf++)) << ((ctx->byteIndex++) * 8);
  }
  SHA3_ASSERT(ctx->byteIndex < 8);
}
/*******************************************************************************************************/
static void const *sha3_Finalize(void *priv) {
  sha3_context *ctx = (sha3_context *) priv;
  ctx->s[ctx->wordIndex] ^= (ctx->saved ^ ((uint64_t) ((uint64_t) (0x02 | (1 << 2)) << ((ctx->byteIndex) * 8))));
  ctx->s[SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords - 1] ^= SHA3_CONST(0x8000000000000000UL);
  keccakf(ctx->s);
  unsigned i;
  for(i = 0; i < SHA3_KECCAK_SPONGE_WORDS; i++) {
    const unsigned t1 = (uint32_t) ctx->s[i];
    const unsigned t2 = (uint32_t) ((ctx->s[i] >> 16) >> 16);
    ctx->sb[i * 8 + 0] = (uint8_t) (t1);
    ctx->sb[i * 8 + 1] = (uint8_t) (t1 >> 8);
    ctx->sb[i * 8 + 2] = (uint8_t) (t1 >> 16);
    ctx->sb[i * 8 + 3] = (uint8_t) (t1 >> 24);
    ctx->sb[i * 8 + 4] = (uint8_t) (t2);
    ctx->sb[i * 8 + 5] = (uint8_t) (t2 >> 8);
    ctx->sb[i * 8 + 6] = (uint8_t) (t2 >> 16);
    ctx->sb[i * 8 + 7] = (uint8_t) (t2 >> 24);
  }
  return (ctx->sb);
}
/*******************************************************************************************************/
void print_hex(uint8_t* str, uint64_t len) {
  uint64_t i;
  for (i = 0; i < len; ++i) {
    if ((i % 64) == 0) { printf("\n"); }
    printf("%.2X", str[i]);
  }
  printf("\n");
}
/*******************************************************************************************************/
char *int2bin(unsigned n, char *buf) {
  #define BITS (sizeof(n) * CHAR_BIT)
  static char static_buf[BITS + 1];
  int i;
  if (buf == NULL) { buf = static_buf; }
  for (i = BITS - 1; i >= 0; --i) {
    buf[i] = (n & 1) ? '1' : '0';
    n >>= 1;
  }
  buf[BITS] = '\0';
  return buf;
  #undef BITS
}
/*******************************************************************************************************/
uint8_t MetaCLU(uint8_t AA, uint8_t BB, int MODE) {
  int meta = (BB % 5);
  switch(meta) {
    case 0:
      if (MODE) { AA = ROL(AA,BB); } else { AA = ROR(AA,BB); }
      break;
    case 1:
       if (MODE) { AA = ROR(AA,BB); } else { AA = ROL(AA,BB); }
      break;
    case 2:
       if (MODE) { AA = XOR(AA,BB); } else { AA = XOR(BB,AA); }
      break;
    case 3:
      AA = INV(AA);
      break;
    case 4:
      AA = NOP(AA);
      break;
  }
  if (DEBUG_META) { printf("M: %d CLU %d: AA = %.2X, BB = %.2X\n",MODE,meta,AA,BB); }
  return AA;
}
/*******************************************************************************************************/
uint32_t MetaCLU32(uint32_t AA, uint32_t BB, int MODE) {
  int meta = (BB % 6);
  switch(meta) {
    case 0:
      if (MODE) { AA = ROL32(AA,BB); } else { AA = ROR32(AA,BB); }
      break;
    case 1:
       if (MODE) { AA = ROR32(AA,BB); } else { AA = ROL32(AA,BB); }
      break;
    case 2:
       if (MODE) { AA = XOR32(AA,BB); } else { AA = XOR32(BB,AA); }
      break;
    case 3:
      AA = INV32(AA);
      break;
    case 4:
      AA = END32(AA);      
    case 5:
      AA = NOP32(AA);
      break;
  }
  return AA;
}
/*******************************************************************************************************/
void gen_sbox(uint8_t byte, uint8_t sbox[256]) {
  uint8_t p = 1, q = 1, xformed;
  do {
    p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);
    q ^= q << 1;
    q ^= q << 2;
    q ^= q << 4;
    q ^= q & 0x80 ? 0x09 : 0;
    xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);
    sbox[p] = xformed ^ byte;
  } while (p != 1);
  sbox[0] = byte;
}
/*******************************************************************************************************/
void print_sbox(uint8_t sbox[256]) {
  int i,j,p;
  for (i = 0; i < 256; i += 16) {
    for (j = 0; j < 16; j++) {
      p = (i+j);
      if (j >= 15) {
        printf("%02X\n",sbox[p]);
      } else {
        printf("%02X ", sbox[p]);
      }
    }
  }
}
/*******************************************************************************************************/
void print_qbox(uint32_t sbox[256]) {
  int i,j,p;
  for (i = 0; i < 256; i += 16) {
    for (j = 0; j < 16; j++) {
      p = (i+j);
      if (j >= 15) {
        printf("%08lX\n",sbox[p]);
      } else {
        printf("%08lX ", sbox[p]);
      }
    }
  }
}
/*******************************************************************************************************/
void gen_ibox(uint8_t sbox[256], uint8_t ibox[256]) {
  uint8_t i = 255;
  do {
    uint8_t p = sbox[i];
    ibox[p] = i;
  } while (i-- != 0);
}
/*******************************************************************************************************/
void shuffle(uint8_t sbox[256]) {
  int i;
  for (i = 255; i >= 0; i--) {
    int j = p_sbox[(PRNG() & 0xFF)];
    int t = sbox[j];
    sbox[j] = sbox[i];
    sbox[i] = t;
  }
}
/*******************************************************************************************************/
void ashuffle(uint32_t sbox[256]) {    
  int i;
  for (i = 255; i >= 0; i--) {
    int j = p_sbox[(PRNG() & 0xFF)];
    int t = sbox[j];
    sbox[j] = sbox[i];
    sbox[i] = t;
  }
}
/*******************************************************************************************************/
void qshuffle() {
  int i,j;
  for (i = 0; i < 11; ++i) {
    for (j = 0; j < 4; ++j) {
      ashuffle(csbox[i][j]);
      print_qbox(csbox[i][j]);
    }
  }
}
/*******************************************************************************************************/
#define getSBoxValue(num) (f_sbox[(num)])
#define getSBoxInvert(num) (i_sbox[(num)])
/*******************************************************************************************************/
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key) {
  unsigned i, j, k;
  uint8_t tempa[4];
  for (i = 0; i < Nk; ++i) {
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }
  for (i = Nk; i < Nb * (Nr + 1); ++i) {
    k = (i - 1) * 4;
    tempa[0]=RoundKey[k + 0];
    tempa[1]=RoundKey[k + 1];
    tempa[2]=RoundKey[k + 2];
    tempa[3]=RoundKey[k + 3];
    if (i % Nk == 0) {
      k = tempa[0];
      tempa[0] = tempa[1];
      tempa[1] = tempa[2];
      tempa[2] = tempa[3];
      tempa[3] = k;
      tempa[0] = getSBoxValue(tempa[0]);
      tempa[1] = getSBoxValue(tempa[1]);
      tempa[2] = getSBoxValue(tempa[2]);
      tempa[3] = getSBoxValue(tempa[3]);
      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
    if (i % Nk == 4) {
      tempa[0] = getSBoxValue(tempa[0]);
      tempa[1] = getSBoxValue(tempa[1]);
      tempa[2] = getSBoxValue(tempa[2]);
      tempa[3] = getSBoxValue(tempa[3]);
    }
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}
/*******************************************************************************************************/
static void AddRoundKey(uint8_t round,state_t* state,uint8_t* RoundKey) {
  uint8_t i,j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
    }
  }
}
/*******************************************************************************************************/
static void AddCubeKey(uint8_t round,state_t* state,uint8_t* RoundKey) {
  uint8_t i,j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      uint8_t x = getSBoxValue(RoundKey[(round * Nb * 4) + (i * Nb) + j]);
      uint8_t y = getSBoxInvert(RoundKey[(round * Nb * 4) + (i * Nb) + j]);
      (*state)[j][i] ^= scube_f[x][y];

    }
  }
}
/*******************************************************************************************************/
static void SubBytes(state_t* state) {
  uint8_t i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      (*state)[j][i] = getSBoxValue((*state)[j][i]);
    }
  }
}
/*******************************************************************************************************/
static void CubeBytes(uint8_t round, state_t* state, uint8_t* RoundKey) {
  uint8_t i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      uint8_t x = RoundKey[(round * Nb * 4) + (i * Nb) + j];
      (*state)[j][i] = scube_f[x][(*state)[j][i]];
    }
  }
}
/*******************************************************************************************************/
static void InvCubeBytes(uint8_t round, state_t* state, uint8_t* RoundKey) {
  uint8_t i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      uint8_t x = RoundKey[(round * Nb * 4) + (i * Nb) + j];
      (*state)[j][i] = scube_i[x][(*state)[j][i]];
    }
  }
}
/*******************************************************************************************************/
static void MetaBytes(uint8_t round, state_t* state,uint8_t* RoundKey) {
  uint8_t i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      uint8_t x = RoundKey[(round * Nb * 4) + (i * Nb) + j];
      (*state)[j][i] = (MetaCLU((*state)[j][i],getSBoxValue(scube_f[x][getSBoxInvert(x)]),0));
    }
  }
}
/*******************************************************************************************************/
static void InvMetaBytes(uint8_t round, state_t* state,uint8_t* RoundKey) {
  uint8_t i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      uint8_t x = RoundKey[(round * Nb * 4) + (i * Nb) + j];
      (*state)[j][i] = (MetaCLU((*state)[j][i],getSBoxValue(scube_f[x][getSBoxInvert(x)]),1));
    }
  }
}
/*******************************************************************************************************/
static void ShiftRows(state_t* state) {
  uint8_t temp;
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;
  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}
/*******************************************************************************************************/
static uint8_t xtime(uint8_t x) { return ((x<<1) ^ (((x>>7) & 1) * 0x1b)); }
/*******************************************************************************************************/
static void MixColumns(state_t* state) {
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i) {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1]; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp;
    Tm  = (*state)[i][1] ^ (*state)[i][2]; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp;
    Tm  = (*state)[i][2] ^ (*state)[i][3]; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp;
    Tm  = (*state)[i][3] ^ t;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp;
  }
}
/*******************************************************************************************************/
static uint8_t Multiply(uint8_t x, uint8_t y) {
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
}
/*******************************************************************************************************/
static void InvMixColumns(state_t* state) {
  int i;
  uint8_t a, b, c, d;
  for (i = 0; i < 4; ++i) { 
    a = (*state)[i][0];
    b = (*state)[i][1];
    c = (*state)[i][2];
    d = (*state)[i][3];
    (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
    (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
    (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
    (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
  }
}
/*******************************************************************************************************/
static void InvSubBytes(state_t* state) {
  uint8_t i, j;
  for (i = 0; i < 4; ++i) {
    for (j = 0; j < 4; ++j) {
      (*state)[j][i] = getSBoxInvert((*state)[j][i]);
    }
  }
}
/*******************************************************************************************************/
static void InvShiftRows(state_t* state) {
  uint8_t temp;
  temp = (*state)[3][1];
  (*state)[3][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[0][1];
  (*state)[0][1] = temp;
  temp = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;
  temp = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;
  temp = (*state)[0][3];
  (*state)[0][3] = (*state)[1][3];
  (*state)[1][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[3][3];
  (*state)[3][3] = temp;
}
/*******************************************************************************************************/
static void Cipher(state_t* state, uint8_t* RoundKey) {
  uint8_t round = 0;
  AddRoundKey(0, state, RoundKey); 
  for (round = 1; round < Nr; ++round) {
    SubBytes(state);
      MetaBytes(round, state, RoundKey);     
      CubeBytes(round, state, RoundKey);
    ShiftRows(state);
      AddCubeKey(round, state, RoundKey);    
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  SubBytes(state);
    MetaBytes(Nr, state, RoundKey);  
    CubeBytes(Nr, state, RoundKey);
  ShiftRows(state);
  AddRoundKey(Nr, state, RoundKey);
}
/*******************************************************************************************************/
static void InvCipher(state_t* state,uint8_t* RoundKey) {
  uint8_t round = 0;
  AddRoundKey(Nr, state, RoundKey);
  for (round = (Nr - 1); round > 0; --round) {
    InvShiftRows(state);
      InvCubeBytes(round+1, state, RoundKey);
      InvMetaBytes(round+1, state, RoundKey);    
    InvSubBytes(state);
    AddRoundKey(round, state, RoundKey);
    InvMixColumns(state);
      AddCubeKey(round, state, RoundKey);
  }
  InvShiftRows(state);
    InvCubeBytes(1, state, RoundKey);
    InvMetaBytes(1, state, RoundKey);   
  InvSubBytes(state);
  AddRoundKey(0, state, RoundKey);
}
/*******************************************************************************************************/
static void MutateBy(uint8_t* AA, uint8_t* BB, int mode) {
  uint8_t i,Drounds,Di,Rrounds,Ri,Mrounds,Mi;
  uint8_t a,b,c,d;
  for (i = 0; i < PRINCESS_BLOCKLEN; i = i + 4) {
    uint32_t L,R,y; uint64_t block; uint32_t x[2];
    a = f_sbox[(BB[i  ] & 0xFF)];
    b = i_sbox[(BB[i+1] & 0xFF)];
    c = f_sbox[(BB[i+2] & 0xFF)];
    d = i_sbox[(BB[i+3] & 0xFF)];
    L = (a | (b << 8) | (c << 16) | (d << 24));
    XBOX_3D(L,R);
    block = CONSTANT_META_3D((((uint64_t)L << 32) | (uint64_t)R));
    x[0] = (block >> 32); x[1] = (block & 0xFFFFFFFF);
    y = (x[0] ^ x[1]);
    a = (y & 0x000000ff);
    b = (y & 0x0000ff00) >> 8;
    c = (y & 0x00ff0000) >> 16;
    d = (y & 0xff000000) >> 24;
    if (mode == 0) {
      Drounds = (1 + (((a^b)^(c^d)) % 4));
      for (Di = 0; Di < Drounds; ++Di) {
        L = (a | (b << 8) | (c << 16) | (d << 24));
        XBOX_3D(L,R);
        block = CONSTANT_META_3D((((uint64_t)L << 32) | (uint64_t)R));
        x[0] = (block >> 32); x[1] = (block & 0xFFFFFFFF);
        y = (x[0] ^ x[1]);
        a = (y & 0x000000ff);
        b = (y & 0x0000ff00) >> 8;
        c = (y & 0x00ff0000) >> 16;
        d = (y & 0xff000000) >> 24;
        Rrounds = (1 + (((a^b)^(c^d)) % 4));
        for (Ri = 0; Ri < Rrounds; ++Ri) {
          a ^= f_sbox[(ROTL8(a, (p_sbox[d] % 8)) & 0xFF)];
          b ^= i_sbox[(ROTR8(b, (p_sbox[c] % 8)) & 0xFF)];
          c ^= f_sbox[(ROTL8(c, (p_sbox[b] % 8)) & 0xFF)];
          d ^= i_sbox[(ROTR8(d, (p_sbox[a] % 8)) & 0xFF)];      
        }
        Mrounds = (1 + (((a^b)^(c^d)) % 4));
        for (Mi = 0; Mi < Rrounds; ++Mi) {
          a ^= MetaCLU(d,a,0);
          b ^= MetaCLU(c,b,1);
          c ^= MetaCLU(b,c,0);
          d ^= MetaCLU(a,d,1);
        }
      }
    }
    AA[i  ] ^= MetaCLU(BB[i  ],a,0);
    AA[i+1] ^= MetaCLU(BB[i+1],b,1);
    AA[i+2] ^= MetaCLU(BB[i+2],c,0);
    AA[i+3] ^= MetaCLU(BB[i+3],d,1);
  }
}
/*******************************************************************************************************/
void BlockCrypt(uint8_t* block, int mode) {
  uint64_t x[2]; uint32_t y[4];
  uint8_t i,j;
  x[0] = CONSTANT_META_3D(PRNG()); 
  x[1] = CONSTANT_META_3D(PRNG()); 
  y[0] = x[0] >> 32; y[1] = x[0] & 0xFFFFFFFF;
  y[2] = x[1] >> 32; y[3] = x[1] & 0xFFFFFFFF;
  j = 0;
  for (i = 0; i < PRINCESS_BLOCKLEN; i = i + 4) {
    block[i  ]  ^= (y[j] & 0x000000ff);
    block[i+1]  ^= (y[j] & 0x0000ff00) >> 8;
    block[i+2]  ^= (y[j] & 0x00ff0000) >> 16;
    block[i+3]  ^= (y[j] & 0xff000000) >> 24;
    ++j;
  }
}
/*******************************************************************************************************/
void RedCrypt(uint8_t *block, int mode) {
  uint64_t a[4]; 
  uint32_t x[4], y[4];
  uint32_t k[8];
  uint8_t i, len;
  len = (1 + (CONSTANT_META_3D(REDPRNG()) % 8));
  for (i = 0; i < len; ++i) {
    x[0] = (block[0 ] | (block[1 ] << 8) | (block[2 ] << 16) | (block[3 ] << 24));
    x[1] = (block[4 ] | (block[5 ] << 8) | (block[6 ] << 16) | (block[7 ] << 24));
    x[2] = (block[8 ] | (block[9 ] << 8) | (block[10] << 16) | (block[11] << 24));
    x[3] = (block[12] | (block[13] << 8) | (block[14] << 16) | (block[15] << 24));
    y[0] = x[0]; y[1] = x[1]; y[2] = x[2]; y[3] = x[3];
    a[0] = CONSTANT_META_3D(REDPRNG()); 
    a[1] = CONSTANT_META_3D(REDPRNG()); 
    a[2] = CONSTANT_META_3D(REDPRNG()); 
    a[3] = CONSTANT_META_3D(REDPRNG());     
    k[0] = a[0] >> 32; k[1] = a[0] & 0xFFFFFFFF;
    k[2] = a[1] >> 32; k[3] = a[1] & 0xFFFFFFFF;
    k[4] = a[2] >> 32; k[5] = a[2] & 0xFFFFFFFF;
    k[6] = a[3] >> 32; k[7] = a[3] & 0xFFFFFFFF;
    if (mode == 0) {
      x[0] ^= k[0]; 
      x[0] ^= ROL32(k[0], k[1]);
      x[1] ^= ROR32(k[1], k[0]); 
      x[1] ^= k[1];
      x[2] ^= k[2]; 
      x[2] ^= ROR32(k[2], k[3]);
      x[3] ^= ROL32(k[3], k[2]); 
      x[3] ^= k[3];

      x[0] ^= MetaCLU32(k[0], k[4], 0);
      x[1] ^= MetaCLU32(k[1], k[5], 0);
      x[2] ^= MetaCLU32(k[2], k[6], 0);
      x[3] ^= MetaCLU32(k[3], k[7], 0);                  
    } else if (mode == 1) {
      x[0] ^= MetaCLU32(k[0], k[4], 0);
      x[1] ^= MetaCLU32(k[1], k[5], 0);
      x[2] ^= MetaCLU32(k[2], k[6], 0);
      x[3] ^= MetaCLU32(k[3], k[7], 0); 

      x[0] ^= ROL32(k[0], k[1]);
      x[0] ^= k[0];
      x[1] ^= k[1];
      x[1] ^= ROR32(k[1], k[0]);
      x[2] ^= ROR32(k[2], k[3]);
      x[2] ^= k[2];
      x[3] ^= k[3]; 
      x[3] ^= ROL32(k[3], k[2]);
    }
    block[0 ] = (x[0] & 0x000000ff);
    block[1 ] = (x[0] & 0x0000ff00) >> 8;
    block[2 ] = (x[0] & 0x00ff0000) >> 16;
    block[3 ] = (x[0] & 0xff000000) >> 24;
    block[4 ] = (x[1] & 0x000000ff);
    block[5 ] = (x[1] & 0x0000ff00) >> 8;
    block[6 ] = (x[1] & 0x00ff0000) >> 16;
    block[7 ] = (x[1] & 0xff000000) >> 24;
    block[8 ] = (x[2] & 0x000000ff);
    block[9 ] = (x[2] & 0x0000ff00) >> 8;
    block[10] = (x[2] & 0x00ff0000) >> 16;
    block[11] = (x[2] & 0xff000000) >> 24;
    block[12] = (x[3] & 0x000000ff);
    block[13] = (x[3] & 0x0000ff00) >> 8;
    block[15] = (x[3] & 0x00ff0000) >> 16;
    block[15] = (x[3] & 0xff000000) >> 24;
    //printf("REDCRYPT: %08lX%08lX%08lX%08lX -> %08lX%08lX%08lX%08lX, ROUND %d (%d)\n", y[0], y[1], y[2], y[3] , x[0], x[1], x[2], x[3], (i+1),len);
  }
}
/*******************************************************************************************************/
void BlueCrypt(uint8_t *block, int mode) {
  uint64_t a[4]; 
  uint32_t x[4], y[4];
  uint32_t k[8];
  uint8_t i, len;
  len = (1 + (CONSTANT_META_3D(BLUEPRNG1()) % 4));
  for (i = 0; i < len; ++i) {
    x[0] = (block[0 ] | (block[1 ] << 8) | (block[2 ] << 16) | (block[3 ] << 24));
    x[1] = (block[4 ] | (block[5 ] << 8) | (block[6 ] << 16) | (block[7 ] << 24));
    x[2] = (block[8 ] | (block[9 ] << 8) | (block[10] << 16) | (block[11] << 24));
    x[3] = (block[12] | (block[13] << 8) | (block[14] << 16) | (block[15] << 24));
    y[0] = x[0]; y[1] = x[1]; y[2] = x[2]; y[3] = x[3];
    a[0] = CONSTANT_META_3D(BLUEPRNG1()); 
    a[1] = CONSTANT_META_3D(BLUEPRNG2()); 
    a[2] = CONSTANT_META_3D(BLUEPRNG1()); 
    a[3] = CONSTANT_META_3D(BLUEPRNG2());     
    k[0] = a[0] >> 32; k[1] = a[0] & 0xFFFFFFFF;
    k[2] = a[1] >> 32; k[3] = a[1] & 0xFFFFFFFF;
    k[4] = a[2] >> 32; k[5] = a[2] & 0xFFFFFFFF;
    k[6] = a[3] >> 32; k[7] = a[3] & 0xFFFFFFFF;
    if (mode == 0) {
      x[0] ^= k[0]; 
      x[0] ^= ROR32(k[0], k[1]);
      x[1] ^= ROL32(k[1], k[0]); 
      x[1] ^= k[1];
      x[2] ^= k[2]; 
      x[2] ^= ROL32(k[2], k[3]);
      x[3] ^= ROR32(k[3], k[2]); 
      x[3] ^= k[3];

      x[0] ^= MetaCLU32(k[0], k[4], 0);
      x[1] ^= MetaCLU32(k[1], k[5], 0);
      x[2] ^= MetaCLU32(k[2], k[6], 0);
      x[3] ^= MetaCLU32(k[3], k[7], 0);                  
    } else if (mode == 1) {
      x[0] ^= MetaCLU32(k[0], k[4], 0);
      x[1] ^= MetaCLU32(k[1], k[5], 0);
      x[2] ^= MetaCLU32(k[2], k[6], 0);
      x[3] ^= MetaCLU32(k[3], k[7], 0); 

      x[0] ^= ROR32(k[0], k[1]);
      x[0] ^= k[0];
      x[1] ^= k[1];
      x[1] ^= ROL32(k[1], k[0]);
      x[2] ^= ROL32(k[2], k[3]);
      x[2] ^= k[2];
      x[3] ^= k[3]; 
      x[3] ^= ROR32(k[3], k[2]);
    }
    block[0 ] = (x[0] & 0x000000ff);
    block[1 ] = (x[0] & 0x0000ff00) >> 8;
    block[2 ] = (x[0] & 0x00ff0000) >> 16;
    block[3 ] = (x[0] & 0xff000000) >> 24;
    block[4 ] = (x[1] & 0x000000ff);
    block[5 ] = (x[1] & 0x0000ff00) >> 8;
    block[6 ] = (x[1] & 0x00ff0000) >> 16;
    block[7 ] = (x[1] & 0xff000000) >> 24;
    block[8 ] = (x[2] & 0x000000ff);
    block[9 ] = (x[2] & 0x0000ff00) >> 8;
    block[10] = (x[2] & 0x00ff0000) >> 16;
    block[11] = (x[2] & 0xff000000) >> 24;
    block[12] = (x[3] & 0x000000ff);
    block[13] = (x[3] & 0x0000ff00) >> 8;
    block[15] = (x[3] & 0x00ff0000) >> 16;
    block[15] = (x[3] & 0xff000000) >> 24;
    //printf("REDCRYPT: %08lX%08lX%08lX%08lX -> %08lX%08lX%08lX%08lX, ROUND %d (%d)\n", y[0], y[1], y[2], y[3] , x[0], x[1], x[2], x[3], (i+1),len);
  }
}
/*******************************************************************************************************/
void HeadCrypt(uint8_t* header) {
  if (DEBUG_HEAD) { dump_header(header); }
  uint64_t x[4];

  int i,j;
  for (i = 0; i < 4096; ++i) {
    for (j = 0; j < 4; ++j) {
      x[j] = CONSTANT_META_3D(CSPRNG()); 
    }

    uint32_t y[8];
    y[0] = x[0] >> 32; y[1] = x[0] & 0xFFFFFFFF;
    y[2] = x[1] >> 32; y[3] = x[1] & 0xFFFFFFFF;
    y[4] = x[2] >> 32; y[5] = x[2] & 0xFFFFFFFF;
    y[6] = x[3] >> 32; y[7] = x[3] & 0xFFFFFFFF;

    header[0]  ^= (y[0] & 0x000000ff);
    header[1]  ^= (y[0] & 0x0000ff00) >> 8;
    header[2]  ^= (y[0] & 0x00ff0000) >> 16;
    header[3]  ^= (y[0] & 0xff000000) >> 24;

    header[4]  ^= (y[1] & 0x000000ff);
    header[5]  ^= (y[1] & 0x0000ff00) >> 8;
    header[6]  ^= (y[1] & 0x00ff0000) >> 16;
    header[7]  ^= (y[1] & 0xff000000) >> 24;  

    header[8]  ^= (y[2] & 0x000000ff);
    header[9]  ^= (y[2] & 0x0000ff00) >> 8;
    header[10] ^= (y[2] & 0x00ff0000) >> 16;
    header[11] ^= (y[2] & 0xff000000) >> 24;

    header[12] ^= (y[3] & 0x000000ff);
    header[13] ^= (y[3] & 0x0000ff00) >> 8;
    header[14] ^= (y[3] & 0x00ff0000) >> 16;
    header[15] ^= (y[3] & 0xff000000) >> 24;  

    header[16] ^= (y[4] & 0x000000ff);
    header[17] ^= (y[4] & 0x0000ff00) >> 8;
    header[18] ^= (y[4] & 0x00ff0000) >> 16;
    header[19] ^= (y[4] & 0xff000000) >> 24;  

    header[20] ^= (y[5] & 0x000000ff);
    header[21] ^= (y[5] & 0x0000ff00) >> 8;
    header[22] ^= (y[5] & 0x00ff0000) >> 16;
    header[23] ^= (y[5] & 0xff000000) >> 24;  

    header[24] ^= (y[6] & 0x000000ff);
    header[25] ^= (y[6] & 0x0000ff00) >> 8;
    header[26] ^= (y[6] & 0x00ff0000) >> 16;
    header[27] ^= (y[6] & 0xff000000) >> 24;  

    header[28] ^= (y[7] & 0x000000ff);
    header[29] ^= (y[7] & 0x0000ff00) >> 8;
    header[30] ^= (y[7] & 0x00ff0000) >> 16;
    header[31] ^= (y[7] & 0xff000000) >> 24;
  }
  if (DEBUG_HEAD) { dump_header(header); }
}
/*******************************************************************************************************/
void PRINCESS_MYST_encrypt_buffer(struct PRINCESS_ctx* ctx, uint8_t* buf, uint32_t length) {
  uintptr_t i;
  uint8_t tmp[PRINCESS_BLOCKLEN];
  int mode = ctx->mode;
  uint8_t *iv_x1 = (ctx->IV_X); uint8_t *iv_x2 = (ctx->IV_X + PRINCESS_BLOCKLEN);
  uint8_t *iv_y1 = (ctx->IV_Y); uint8_t *iv_y2 = (ctx->IV_Y + PRINCESS_BLOCKLEN);     
  for (i = 0; i < length; i += PRINCESS_BLOCKLEN) {
    memcpy(tmp, buf, PRINCESS_BLOCKLEN);
    int meta = (i % 2);
    switch(meta) {
      case 0:
        MutateBy(buf, iv_x1, mode);
        BlueCrypt(buf,0);
        Cipher((state_t*)buf, ctx->RoundKey); 
        BlockCrypt(buf,mode);
        RedCrypt(buf,0);
        MutateBy(buf, iv_x2, mode);
        break;
      case 1:
        MutateBy(buf, iv_y1, mode);
        BlueCrypt(buf,0);        
        Cipher((state_t*)buf, ctx->RoundKey); 
        BlockCrypt(buf,mode);
        RedCrypt(buf,0);
        MutateBy(buf, iv_y2, mode);    
        break;
    }
    iv_x1 = buf;
    iv_y1 = buf;
    memcpy(iv_x2, tmp, PRINCESS_BLOCKLEN);
    memcpy(iv_y2, tmp, PRINCESS_BLOCKLEN);    
    buf += PRINCESS_BLOCKLEN;    
  }  
  memcpy(ctx->IV_X, iv_x1, PRINCESS_BLOCKLEN);
  memcpy(ctx->IV_Y, iv_y1, PRINCESS_BLOCKLEN);  
}
/*******************************************************************************************************/
void PRINCESS_MYST_decrypt_buffer(struct PRINCESS_ctx* ctx, uint8_t* buf, uint32_t length) {
  uintptr_t i;
  uint8_t tmp[PRINCESS_BLOCKLEN];
  int mode = ctx->mode;  
  uint8_t *iv_x1 = (ctx->IV_X); uint8_t *iv_x2 = (ctx->IV_X + PRINCESS_BLOCKLEN);
  uint8_t *iv_y1 = (ctx->IV_Y); uint8_t *iv_y2 = (ctx->IV_Y + PRINCESS_BLOCKLEN);    
  for (i = 0; i < length; i += PRINCESS_BLOCKLEN) {
    memcpy(tmp, buf, PRINCESS_BLOCKLEN);    
    int meta = (i % 2);
    switch(meta) {
      case 0:
        MutateBy(buf, iv_x2, mode);
        RedCrypt(buf,1);
        BlockCrypt(buf,mode); 
        InvCipher((state_t*)buf, ctx->RoundKey);
        BlueCrypt(buf,1);        
        MutateBy(buf, iv_x1, mode);
        break;
      case 1:
        MutateBy(buf, iv_y2, mode);
        RedCrypt(buf,1); 
        BlockCrypt(buf,mode); 
        InvCipher((state_t*)buf, ctx->RoundKey);
        BlueCrypt(buf,1);        
        MutateBy(buf, iv_y1, mode);
        break;
    }
    memcpy(iv_x1, tmp, PRINCESS_BLOCKLEN);
    memcpy(iv_y1, tmp, PRINCESS_BLOCKLEN);    
    iv_x2 = buf;
    iv_y2 = buf;
    buf += PRINCESS_BLOCKLEN;
  }
  memcpy(ctx->IV_X + PRINCESS_BLOCKLEN, iv_x2, PRINCESS_BLOCKLEN);
  memcpy(ctx->IV_Y + PRINCESS_BLOCKLEN, iv_y2, PRINCESS_BLOCKLEN);  
}
/*******************************************************************************************************/
uint64_t ENHASH(uint64_t input, uint64_t loop) {
  uint64_t i, output; output = input;
  for (i = 0;i < loop;i++) { output ^= CONSTANT_META_3D(IVCSPRNG()); }
  return output;
}
/*******************************************************************************************************/
uint8_t ENBOX(uint8_t input, uint8_t loop) {
  uint8_t i, output; output = input;
  for (i = 0;i < loop;i++) { output = (p_sbox[(output % 0xFF)] & 0xFF); }
  return output;
}
/*******************************************************************************************************/
void whitening(uint8_t *input, int len) {

/*
    csbox[( % 11)][( % 4)][]

    x[0] = (block[0 ] | (block[1 ] << 8) | (block[2 ] << 16) | (block[3 ] << 24));
    x[1] = (block[4 ] | (block[5 ] << 8) | (block[6 ] << 16) | (block[7 ] << 24));
    x[2] = (block[8 ] | (block[9 ] << 8) | (block[10] << 16) | (block[11] << 24));
    x[3] = (block[12] | (block[13] << 8) | (block[14] << 16) | (block[15] << 24));
*/

}
/*******************************************************************************************************/
void PRINCESS_init_preboot(struct PRINCESS_ctx* ctx, const uint8_t* password, int passlen, int mode) {
  int tseed = time(NULL); srand(tseed);  
  sha3_context c;
  const uint8_t *hash;

  sha3_Init256(&c);
  sha3_Update(&c,password, passlen);  
  hash = sha3_Finalize(&c);
 
  uint64_t sha3_bytes64;
  (sha3_bytes64 = (((uint64_t)((hash)[0] & 0xFF)) << 56) | (((uint64_t)((hash)[1] & 0xFF)) << 48) | \
                  (((uint64_t)((hash)[2] & 0xFF)) << 40) | (((uint64_t)((hash)[3] & 0xFF)) << 32) | \
                  (((uint64_t)((hash)[4] & 0xFF)) << 24) | (((uint64_t)((hash)[5] & 0xFF)) << 16) | \
                  (((uint64_t)((hash)[6] & 0xFF)) <<  8) | (((uint64_t)((hash)[7] & 0xFF))));


  memset(p_sbox, 0, 256);
  memset(f_sbox, 0, 256);
  memset(i_sbox, 0, 256);
  uint8_t byte = (sha3_bytes64 & 0xFF );
  gen_sbox(byte, p_sbox);


  uint32_t sha3_bytes32[2];
  sha3_bytes32[0] = sha3_bytes64 >> 32; 
  sha3_bytes32[1] = sha3_bytes64 & 0xFFFFFFFF;
  
  uint32_t sha3_m = sha3_bytes32[0];
  uint32_t sha3_x = sha3_bytes32[1];
  uint32_t sha3_o = XBOX_MUTATE_2D(sha3_m,sha3_x);

  int sha3_i, sha3_j;
  int sha3_len = (4096 + (sha3_o % 1747));
  for(sha3_i = 0; sha3_i < sha3_len; ++sha3_i){ 
    uint8_t *tmphash = (uint8_t *)hash;
    for (sha3_j = 0; sha3_j < 200; ++sha3_j) { 
      tmphash[sha3_j] = MetaCLU(tmphash[sha3_j],ENBOX(p_sbox[(sha3_j % 0xFF)], p_sbox[(tmphash[(p_sbox[(sha3_j % 0xFF)] % 200)] & 0xFF)]),(tmphash[sha3_j] % 2));
    }
    sha3_Update(&c,tmphash, 200);
    hash = sha3_Finalize(&c);    
  }
  
  uint64_t A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P; //abcdefghijklmnopqrstuvwxyz
  (A = (((uint64_t)((hash)[0] & 0xFF)) << 56) | (((uint64_t)((hash)[1] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[2] & 0xFF)) << 40) | (((uint64_t)((hash)[3] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[4] & 0xFF)) << 24) | (((uint64_t)((hash)[5] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[6] & 0xFF)) <<  8) | (((uint64_t)((hash)[7] & 0xFF))));

  (B = (((uint64_t)((hash)[8] & 0xFF)) << 56) | (((uint64_t)((hash)[9] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[10] & 0xFF)) << 40) | (((uint64_t)((hash)[11] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[12] & 0xFF)) << 24) | (((uint64_t)((hash)[13] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[14] & 0xFF)) <<  8) | (((uint64_t)((hash)[15] & 0xFF))));
  
  (C = (((uint64_t)((hash)[16] & 0xFF)) << 56) | (((uint64_t)((hash)[17] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[18] & 0xFF)) << 40) | (((uint64_t)((hash)[19] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[20] & 0xFF)) << 24) | (((uint64_t)((hash)[21] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[22] & 0xFF)) <<  8) | (((uint64_t)((hash)[23] & 0xFF))));

  (D = (((uint64_t)((hash)[24] & 0xFF)) << 56) | (((uint64_t)((hash)[25] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[26] & 0xFF)) << 40) | (((uint64_t)((hash)[27] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[28] & 0xFF)) << 24) | (((uint64_t)((hash)[29] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[30] & 0xFF)) <<  8) | (((uint64_t)((hash)[31] & 0xFF))));

  (E = (((uint64_t)((hash)[32] & 0xFF)) << 56) | (((uint64_t)((hash)[33] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[34] & 0xFF)) << 40) | (((uint64_t)((hash)[35] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[36] & 0xFF)) << 24) | (((uint64_t)((hash)[37] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[38] & 0xFF)) <<  8) | (((uint64_t)((hash)[39] & 0xFF))));

  (F = (((uint64_t)((hash)[40] & 0xFF)) << 56) | (((uint64_t)((hash)[41] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[42] & 0xFF)) << 40) | (((uint64_t)((hash)[43] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[44] & 0xFF)) << 24) | (((uint64_t)((hash)[45] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[46] & 0xFF)) <<  8) | (((uint64_t)((hash)[47] & 0xFF))));

  (G = (((uint64_t)((hash)[48] & 0xFF)) << 56) | (((uint64_t)((hash)[49] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[50] & 0xFF)) << 40) | (((uint64_t)((hash)[51] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[52] & 0xFF)) << 24) | (((uint64_t)((hash)[53] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[54] & 0xFF)) <<  8) | (((uint64_t)((hash)[55] & 0xFF))));  

  (H = (((uint64_t)((hash)[56] & 0xFF)) << 56) | (((uint64_t)((hash)[57] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[58] & 0xFF)) << 40) | (((uint64_t)((hash)[59] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[60] & 0xFF)) << 24) | (((uint64_t)((hash)[61] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[62] & 0xFF)) <<  8) | (((uint64_t)((hash)[63] & 0xFF))));

  (I = (((uint64_t)((hash)[64] & 0xFF)) << 56) | (((uint64_t)((hash)[65] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[66] & 0xFF)) << 40) | (((uint64_t)((hash)[67] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[68] & 0xFF)) << 24) | (((uint64_t)((hash)[69] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[70] & 0xFF)) <<  8) | (((uint64_t)((hash)[71] & 0xFF))));

  (J = (((uint64_t)((hash)[72] & 0xFF)) << 56) | (((uint64_t)((hash)[73] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[74] & 0xFF)) << 40) | (((uint64_t)((hash)[75] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[76] & 0xFF)) << 24) | (((uint64_t)((hash)[77] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[78] & 0xFF)) <<  8) | (((uint64_t)((hash)[79] & 0xFF))));

  (K = (((uint64_t)((hash)[80] & 0xFF)) << 56) | (((uint64_t)((hash)[81] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[82] & 0xFF)) << 40) | (((uint64_t)((hash)[83] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[84] & 0xFF)) << 24) | (((uint64_t)((hash)[85] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[86] & 0xFF)) <<  8) | (((uint64_t)((hash)[87] & 0xFF))));  

  (L = (((uint64_t)((hash)[88] & 0xFF)) << 56) | (((uint64_t)((hash)[89] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[90] & 0xFF)) << 40) | (((uint64_t)((hash)[91] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[92] & 0xFF)) << 24) | (((uint64_t)((hash)[93] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[94] & 0xFF)) <<  8) | (((uint64_t)((hash)[95] & 0xFF))));

  (M = (((uint64_t)((hash)[ 96] & 0xFF)) << 56) | (((uint64_t)((hash)[ 97] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[ 98] & 0xFF)) << 40) | (((uint64_t)((hash)[ 99] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[100] & 0xFF)) << 24) | (((uint64_t)((hash)[101] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[102] & 0xFF)) <<  8) | (((uint64_t)((hash)[103] & 0xFF))));

  (N = (((uint64_t)((hash)[104] & 0xFF)) << 56) | (((uint64_t)((hash)[105] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[106] & 0xFF)) << 40) | (((uint64_t)((hash)[107] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[108] & 0xFF)) << 24) | (((uint64_t)((hash)[109] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[110] & 0xFF)) <<  8) | (((uint64_t)((hash)[111] & 0xFF))));

  (O = (((uint64_t)((hash)[112] & 0xFF)) << 56) | (((uint64_t)((hash)[113] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[114] & 0xFF)) << 40) | (((uint64_t)((hash)[115] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[116] & 0xFF)) << 24) | (((uint64_t)((hash)[117] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[118] & 0xFF)) <<  8) | (((uint64_t)((hash)[119] & 0xFF))));

  (P = (((uint64_t)((hash)[120] & 0xFF)) << 56) | (((uint64_t)((hash)[121] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[122] & 0xFF)) << 40) | (((uint64_t)((hash)[123] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[124] & 0xFF)) << 24) | (((uint64_t)((hash)[125] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[126] & 0xFF)) <<  8) | (((uint64_t)((hash)[127] & 0xFF))));

  if (DEBUG_KEYS) { 
    printf("SHA3 1 (512bit): %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n",A,B,C,D,E,F,G,H);    
    printf("SHA3 2 (512bit): %016llX %016llX %016llX %016llX %016llX %016llX %016llX %016llX\n",I,J,K,L,M,N,O,P);   
  }
  uint64_t seed[8] = { A,B,C,D,E,F,G,H };
  PRNG_BOOT(seed);
  printf("\n\n");

  gen_sbox(byte, f_sbox);
  shuffle(f_sbox);
  gen_ibox(f_sbox, i_sbox);  
  if (DEBUG_SBOX) {
    printf("\nSBOX ID: %02X\n",byte);
    printf("PRNG SBOX:\n");
    print_sbox(p_sbox);
    printf("\nFORWARD DYNAMIC SBOX:\n");
    print_sbox(f_sbox);
    printf("\nINVERSE DYNAMIC SBOX:\n");
    print_sbox(i_sbox);
    printf("\n\n");
  }
  int cube_i;
  for (cube_i = 0; cube_i < 256; ++cube_i) {
    memset(scube_f[cube_i], 0, 256);
    memset(scube_i[cube_i], 0, 256);    
    gen_sbox(f_sbox[(CSPRNG() & 0xFF)], scube_f[cube_i]);
    shuffle(scube_f[cube_i]);
    //printf("\nDYNAMIC FOWRARD S-CUBE[%d]:\n",cube_i); print_sbox(scube_f[cube_i]);    
    gen_ibox(scube_f[cube_i], scube_i[cube_i]);
    //printf("\nDYNAMIC INVERSE S-CUBE[%d]:\n",cube_i); print_sbox(scube_i[cube_i]);    
  }
  qshuffle();

  XS_IV_s[0] = CONSTANT_META_3D(CSPRNG());
  XS_IV_s[1] = CONSTANT_META_3D(CSPRNG());

  RED_S1[0] = CONSTANT_META_3D(CSPRNG());
  RED_S1[1] = CONSTANT_META_3D(CSPRNG());

  BLUE_s1[0] = CONSTANT_META_3D(CSPRNG());
  BLUE_s1[1] = CONSTANT_META_3D(CSPRNG());

  BLUE_s2[0] = CONSTANT_META_3D(CSPRNG());
  BLUE_s2[1] = CONSTANT_META_3D(CSPRNG());


  if (DEBUG_KEYS) { printf("IVPRNG SEED (128bit): %016llX %016llX\n",XS_IV_s[0],XS_IV_s[1]); }

  printf("REDPRNG SEED (128bit): %016llX %016llX\n",RED_S1[0],RED_S1[1]);

  uint8_t iv_x_bytes[32];
  uint8_t iv_y_bytes[32];

  if (mode == 0) {

    uint32_t iv_x1[2], iv_x2[2], iv_x3[2], iv_x4[2];

    iv_x1[0] = I >> 32; iv_x1[1] = I & 0xFFFFFFFF;
    iv_x2[0] = J >> 32; iv_x2[1] = J & 0xFFFFFFFF;
    iv_x3[0] = K >> 32; iv_x3[1] = K & 0xFFFFFFFF;
    iv_x4[0] = L >> 32; iv_x4[1] = L & 0xFFFFFFFF;

    iv_x1[0] ^= XBOX_MUTATE_3D(A,iv_x1[0]);
    iv_x1[0] ^= XBOX_MUTATE_3D(B,iv_x1[0]);
    iv_x2[0] ^= XBOX_MUTATE_3D(C,iv_x2[0]);
    iv_x2[0] ^= XBOX_MUTATE_3D(D,iv_x2[0]);
    iv_x3[0] ^= XBOX_MUTATE_3D(E,iv_x3[0]);
    iv_x3[0] ^= XBOX_MUTATE_3D(F,iv_x3[0]);
    iv_x4[0] ^= XBOX_MUTATE_3D(G,iv_x4[0]);
    iv_x4[0] ^= XBOX_MUTATE_3D(H,iv_x4[0]);

    iv_x1[0] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);
    iv_x1[1] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);
    iv_x2[0] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);
    iv_x2[1] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);
    iv_x3[0] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);
    iv_x3[1] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);
    iv_x4[0] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);
    iv_x4[1] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);

    iv_x1[0] ^= XBOX_MUTATE_3D(I,iv_x1[0]);
    iv_x1[0] ^= XBOX_MUTATE_3D(J,iv_x1[0]);
    iv_x2[0] ^= XBOX_MUTATE_3D(K,iv_x2[0]);
    iv_x2[0] ^= XBOX_MUTATE_3D(L,iv_x2[0]);
    iv_x3[0] ^= XBOX_MUTATE_3D(M,iv_x3[0]);
    iv_x3[0] ^= XBOX_MUTATE_3D(N,iv_x3[0]);
    iv_x4[0] ^= XBOX_MUTATE_3D(O,iv_x4[0]);
    iv_x4[0] ^= XBOX_MUTATE_3D(P,iv_x4[0]);

    uint32_t aes_iv_x[8] = { iv_x1[0], iv_x1[1], iv_x2[0], iv_x2[1], iv_x3[0], iv_x3[1], iv_x4[0], iv_x4[1] };

    iv_x_bytes[0]  = (aes_iv_x[0] & 0x000000ff);
    iv_x_bytes[1]  = (aes_iv_x[0] & 0x0000ff00) >> 8;
    iv_x_bytes[2]  = (aes_iv_x[0] & 0x00ff0000) >> 16;
    iv_x_bytes[3]  = (aes_iv_x[0] & 0xff000000) >> 24;

    iv_x_bytes[4]  = (aes_iv_x[1] & 0x000000ff);
    iv_x_bytes[5]  = (aes_iv_x[1] & 0x0000ff00) >> 8;
    iv_x_bytes[6]  = (aes_iv_x[1] & 0x00ff0000) >> 16;
    iv_x_bytes[7]  = (aes_iv_x[1] & 0xff000000) >> 24;

    iv_x_bytes[8]  = (aes_iv_x[2] & 0x000000ff);
    iv_x_bytes[9]  = (aes_iv_x[2] & 0x0000ff00) >> 8;
    iv_x_bytes[10] = (aes_iv_x[2] & 0x00ff0000) >> 16;
    iv_x_bytes[11] = (aes_iv_x[2] & 0xff000000) >> 24;

    iv_x_bytes[12] = (aes_iv_x[3] & 0x000000ff);
    iv_x_bytes[13] = (aes_iv_x[3] & 0x0000ff00) >> 8;
    iv_x_bytes[14] = (aes_iv_x[3] & 0x00ff0000) >> 16;
    iv_x_bytes[15] = (aes_iv_x[3] & 0xff000000) >> 24;

    iv_x_bytes[16] = (aes_iv_x[4] & 0x000000ff);
    iv_x_bytes[17] = (aes_iv_x[4] & 0x0000ff00) >> 8;
    iv_x_bytes[18] = (aes_iv_x[4] & 0x00ff0000) >> 16;
    iv_x_bytes[19] = (aes_iv_x[4] & 0xff000000) >> 24;

    iv_x_bytes[20] = (aes_iv_x[5] & 0x000000ff);
    iv_x_bytes[21] = (aes_iv_x[5] & 0x0000ff00) >> 8;
    iv_x_bytes[22] = (aes_iv_x[5] & 0x00ff0000) >> 16;
    iv_x_bytes[23] = (aes_iv_x[5] & 0xff000000) >> 24;

    iv_x_bytes[24] = (aes_iv_x[6] & 0x000000ff);
    iv_x_bytes[25] = (aes_iv_x[6] & 0x0000ff00) >> 8;
    iv_x_bytes[26] = (aes_iv_x[6] & 0x00ff0000) >> 16;
    iv_x_bytes[27] = (aes_iv_x[6] & 0xff000000) >> 24;

    iv_x_bytes[28] = (aes_iv_x[7] & 0x000000ff);
    iv_x_bytes[29] = (aes_iv_x[7] & 0x0000ff00) >> 8;
    iv_x_bytes[30] = (aes_iv_x[7] & 0x00ff0000) >> 16;
    iv_x_bytes[31] = (aes_iv_x[7] & 0xff000000) >> 24;

    if (DEBUG_KEYS) { printf("PRINCESS MYST IV X (256bit): %08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX\n", aes_iv_x[0], aes_iv_x[1], aes_iv_x[2], aes_iv_x[3], aes_iv_x[4], aes_iv_x[5], aes_iv_x[6], aes_iv_x[7]); }

    uint32_t iv_y1[2], iv_y2[2], iv_y3[2], iv_y4[2];

    iv_y1[0] = (A^E) >> 32; iv_y1[1] = (A^E) & 0xFFFFFFFF;
    iv_y2[0] = (B^F) >> 32; iv_y2[1] = (B^F) & 0xFFFFFFFF;
    iv_y3[0] = (C^G) >> 32; iv_y3[1] = (C^G) & 0xFFFFFFFF;
    iv_y4[0] = (D^H) >> 32; iv_y4[1] = (D^H) & 0xFFFFFFFF;

    iv_y1[0] ^= XBOX_MUTATE_3D(M,iv_y1[0]);
    iv_y1[1] ^= XBOX_MUTATE_3D(M,iv_y1[1]);
    iv_y2[0] ^= XBOX_MUTATE_3D(N,iv_y2[0]);
    iv_y2[1] ^= XBOX_MUTATE_3D(N,iv_y2[1]);
    iv_y3[0] ^= XBOX_MUTATE_3D(O,iv_y3[0]);
    iv_y3[1] ^= XBOX_MUTATE_3D(O,iv_y3[1]);
    iv_y4[0] ^= XBOX_MUTATE_3D(P,iv_y4[0]);
    iv_y4[1] ^= XBOX_MUTATE_3D(P,iv_y4[1]);

    iv_y1[0] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);
    iv_y1[1] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);
    iv_y2[0] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);
    iv_y2[1] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);
    iv_y3[0] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);
    iv_y3[1] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);
    iv_y4[0] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);
    iv_y4[1] ^= ENHASH(IVCSPRNG(),(uint64_t)f_sbox[(rand() & 0xFF)]);

    iv_y1[0] ^= XBOX_MUTATE_3D(A,iv_y1[0]);
    iv_y1[1] ^= XBOX_MUTATE_3D(B,iv_y1[1]);
    iv_y2[0] ^= XBOX_MUTATE_3D(C,iv_y2[0]);
    iv_y2[1] ^= XBOX_MUTATE_3D(D,iv_y2[1]);
    iv_y3[0] ^= XBOX_MUTATE_3D(E,iv_y3[0]);
    iv_y3[1] ^= XBOX_MUTATE_3D(F,iv_y3[1]);
    iv_y4[0] ^= XBOX_MUTATE_3D(G,iv_y4[0]);
    iv_y4[1] ^= XBOX_MUTATE_3D(H,iv_y4[1]);

    uint32_t aes_iv_y[8] = { iv_y1[0], iv_y1[1], iv_y2[0], iv_y2[1], iv_y3[0], iv_y3[1], iv_y4[0], iv_y4[1] };

    iv_y_bytes[0]  = (aes_iv_y[0] & 0x000000ff);
    iv_y_bytes[1]  = (aes_iv_y[0] & 0x0000ff00) >> 8;
    iv_y_bytes[2]  = (aes_iv_y[0] & 0x00ff0000) >> 16;
    iv_y_bytes[3]  = (aes_iv_y[0] & 0xff000000) >> 24;

    iv_y_bytes[4]  = (aes_iv_y[1] & 0x000000ff);
    iv_y_bytes[5]  = (aes_iv_y[1] & 0x0000ff00) >> 8;
    iv_y_bytes[6]  = (aes_iv_y[1] & 0x00ff0000) >> 16;
    iv_y_bytes[7]  = (aes_iv_y[1] & 0xff000000) >> 24;

    iv_y_bytes[8]  = (aes_iv_y[2] & 0x000000ff);
    iv_y_bytes[9]  = (aes_iv_y[2] & 0x0000ff00) >> 8;
    iv_y_bytes[10] = (aes_iv_y[2] & 0x00ff0000) >> 16;
    iv_y_bytes[11] = (aes_iv_y[2] & 0xff000000) >> 24;

    iv_y_bytes[12] = (aes_iv_y[3] & 0x000000ff);
    iv_y_bytes[13] = (aes_iv_y[3] & 0x0000ff00) >> 8;
    iv_y_bytes[14] = (aes_iv_y[3] & 0x00ff0000) >> 16;
    iv_y_bytes[15] = (aes_iv_y[3] & 0xff000000) >> 24;

    iv_y_bytes[16] = (aes_iv_y[4] & 0x000000ff);
    iv_y_bytes[17] = (aes_iv_y[4] & 0x0000ff00) >> 8;
    iv_y_bytes[18] = (aes_iv_y[4] & 0x00ff0000) >> 16;
    iv_y_bytes[19] = (aes_iv_y[4] & 0xff000000) >> 24;

    iv_y_bytes[20] = (aes_iv_y[5] & 0x000000ff);
    iv_y_bytes[21] = (aes_iv_y[5] & 0x0000ff00) >> 8;
    iv_y_bytes[22] = (aes_iv_y[5] & 0x00ff0000) >> 16;
    iv_y_bytes[23] = (aes_iv_y[5] & 0xff000000) >> 24;

    iv_y_bytes[24] = (aes_iv_y[6] & 0x000000ff);
    iv_y_bytes[25] = (aes_iv_y[6] & 0x0000ff00) >> 8;
    iv_y_bytes[26] = (aes_iv_y[6] & 0x00ff0000) >> 16;
    iv_y_bytes[27] = (aes_iv_y[6] & 0xff000000) >> 24;

    iv_y_bytes[28] = (aes_iv_y[7] & 0x000000ff);
    iv_y_bytes[29] = (aes_iv_y[7] & 0x0000ff00) >> 8;
    iv_y_bytes[30] = (aes_iv_y[7] & 0x00ff0000) >> 16;
    iv_y_bytes[31] = (aes_iv_y[7] & 0xff000000) >> 24;

    if (DEBUG_KEYS) { printf("PRINCESS MYST IV Y (256bit): %08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX\n", aes_iv_y[0], aes_iv_y[1], aes_iv_y[2], aes_iv_y[3], aes_iv_y[4], aes_iv_y[5], aes_iv_y[6], aes_iv_y[7]); }
  }
  uint32_t key1[2], key2[2], key3[2], key4[2];

  key1[0] = M >> 32; key1[1] = M & 0xFFFFFFFF;
  key2[0] = N >> 32; key2[1] = N & 0xFFFFFFFF;
  key3[0] = O >> 32; key3[1] = O & 0xFFFFFFFF;
  key4[0] = P >> 32; key4[1] = P & 0xFFFFFFFF;
  
  key1[0] ^= XBOX_MUTATE_3D(A,key1[0]);
  key1[1] ^= XBOX_MUTATE_3D(B,key1[1]);
  key2[0] ^= XBOX_MUTATE_3D(C,key2[0]);
  key2[1] ^= XBOX_MUTATE_3D(D,key2[1]);
  key3[0] ^= XBOX_MUTATE_3D(E,key3[0]);
  key3[1] ^= XBOX_MUTATE_3D(F,key3[1]);
  key4[0] ^= XBOX_MUTATE_3D(G,key4[0]);
  key4[1] ^= XBOX_MUTATE_3D(H,key4[1]);

  uint32_t aes_key[8]  = { key1[0], key1[1], key2[0], key2[1], key3[0], key3[1], key4[0], key4[1] };

  uint8_t key_bytes[32];
  key_bytes[0]  = (aes_key[0] & 0x000000ff);
  key_bytes[1]  = (aes_key[0] & 0x0000ff00) >> 8;
  key_bytes[2]  = (aes_key[0] & 0x00ff0000) >> 16;
  key_bytes[3]  = (aes_key[0] & 0xff000000) >> 24;

  key_bytes[4]  = (aes_key[1] & 0x000000ff);
  key_bytes[5]  = (aes_key[1] & 0x0000ff00) >> 8;
  key_bytes[6]  = (aes_key[1] & 0x00ff0000) >> 16;
  key_bytes[7]  = (aes_key[1] & 0xff000000) >> 24;

  key_bytes[8]  = (aes_key[2] & 0x000000ff);
  key_bytes[9]  = (aes_key[2] & 0x0000ff00) >> 8;
  key_bytes[10] = (aes_key[2] & 0x00ff0000) >> 16;
  key_bytes[11] = (aes_key[2] & 0xff000000) >> 24;

  key_bytes[12] = (aes_key[3] & 0x000000ff);
  key_bytes[13] = (aes_key[3] & 0x0000ff00) >> 8;
  key_bytes[14] = (aes_key[3] & 0x00ff0000) >> 16;
  key_bytes[15] = (aes_key[3] & 0xff000000) >> 24;

  key_bytes[16] = (aes_key[4] & 0x000000ff);
  key_bytes[17] = (aes_key[4] & 0x0000ff00) >> 8;
  key_bytes[18] = (aes_key[4] & 0x00ff0000) >> 16;
  key_bytes[19] = (aes_key[4] & 0xff000000) >> 24;

  key_bytes[20] = (aes_key[5] & 0x000000ff);
  key_bytes[21] = (aes_key[5] & 0x0000ff00) >> 8;
  key_bytes[22] = (aes_key[5] & 0x00ff0000) >> 16;
  key_bytes[23] = (aes_key[5] & 0xff000000) >> 24;

  key_bytes[24] = (aes_key[6] & 0x000000ff);
  key_bytes[25] = (aes_key[6] & 0x0000ff00) >> 8;
  key_bytes[26] = (aes_key[6] & 0x00ff0000) >> 16;
  key_bytes[27] = (aes_key[6] & 0xff000000) >> 24;

  key_bytes[28] = (aes_key[7] & 0x000000ff);
  key_bytes[29] = (aes_key[7] & 0x0000ff00) >> 8;
  key_bytes[30] = (aes_key[7] & 0x00ff0000) >> 16;
  key_bytes[31] = (aes_key[7] & 0xff000000) >> 24;

  if (DEBUG_KEYS) { 
    printf("PRINCESS MYST KEY (256bit): %08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX\n", aes_key[0], aes_key[1], aes_key[2], aes_key[3], aes_key[4], aes_key[5], aes_key[6], aes_key[7]);
    printf("\n\n");
  }
  KeyExpansion(ctx->RoundKey, key_bytes);
  if (mode == 0) {
    memcpy (ctx->IV_X, iv_x_bytes, 2 * PRINCESS_BLOCKLEN);
    memcpy (ctx->IV_Y, iv_y_bytes, 2 * PRINCESS_BLOCKLEN);
  }
  printf("READY\n\n");  
}
/*******************************************************************************************************/
void dump_header(uint8_t* header) {
  uint32_t head[8];
  head[0] = (header[0 ] | (header[1 ] << 8) | (header[2 ] << 16) | (header[3 ] << 24));
  head[1] = (header[4 ] | (header[5 ] << 8) | (header[6 ] << 16) | (header[7 ] << 24));
  head[2] = (header[8 ] | (header[9 ] << 8) | (header[10] << 16) | (header[11] << 24));
  head[3] = (header[12] | (header[13] << 8) | (header[14] << 16) | (header[15] << 24));
  head[4] = (header[16] | (header[17] << 8) | (header[18] << 16) | (header[19] << 24));
  head[5] = (header[20] | (header[21] << 8) | (header[22] << 16) | (header[23] << 24));
  head[6] = (header[24] | (header[25] << 8) | (header[26] << 16) | (header[27] << 24));
  head[7] = (header[28] | (header[29] << 8) | (header[30] << 16) | (header[31] << 24));
  printf("HEAD (256bit): %08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX\n", head[0], head[1], head[2], head[3], head[4], head[5], head[6], head[7]);
}
/*******************************************************************************************************/
void dump_keys(struct PRINCESS_ctx* ctx) {

  uint8_t iv_x_bytes[32]; memcpy (iv_x_bytes, ctx->IV_X, 32); uint32_t x_iv[8];
  x_iv[0] = (iv_x_bytes[0 ] | (iv_x_bytes[1 ] << 8) | (iv_x_bytes[2 ] << 16) | (iv_x_bytes[3 ] << 24));
  x_iv[1] = (iv_x_bytes[4 ] | (iv_x_bytes[5 ] << 8) | (iv_x_bytes[6 ] << 16) | (iv_x_bytes[7 ] << 24));
  x_iv[2] = (iv_x_bytes[8 ] | (iv_x_bytes[9 ] << 8) | (iv_x_bytes[10] << 16) | (iv_x_bytes[11] << 24));
  x_iv[3] = (iv_x_bytes[12] | (iv_x_bytes[13] << 8) | (iv_x_bytes[14] << 16) | (iv_x_bytes[15] << 24));
  x_iv[4] = (iv_x_bytes[16] | (iv_x_bytes[17] << 8) | (iv_x_bytes[18] << 16) | (iv_x_bytes[19] << 24));
  x_iv[5] = (iv_x_bytes[20] | (iv_x_bytes[21] << 8) | (iv_x_bytes[22] << 16) | (iv_x_bytes[23] << 24));
  x_iv[6] = (iv_x_bytes[24] | (iv_x_bytes[25] << 8) | (iv_x_bytes[26] << 16) | (iv_x_bytes[27] << 24));
  x_iv[7] = (iv_x_bytes[28] | (iv_x_bytes[29] << 8) | (iv_x_bytes[30] << 16) | (iv_x_bytes[31] << 24));

  printf("IV X (256bit): %08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX\n", x_iv[0], x_iv[1], x_iv[2], x_iv[3], x_iv[4], x_iv[5], x_iv[6], x_iv[7]);

  uint8_t iv_y_bytes[32]; memcpy (iv_y_bytes, ctx->IV_Y, 32); uint32_t y_iv[8];
  y_iv[0] = (iv_y_bytes[0 ] | (iv_y_bytes[1 ] << 8) | (iv_y_bytes[2 ] << 16) | (iv_y_bytes[3 ] << 24));
  y_iv[1] = (iv_y_bytes[4 ] | (iv_y_bytes[5 ] << 8) | (iv_y_bytes[6 ] << 16) | (iv_y_bytes[7 ] << 24));
  y_iv[2] = (iv_y_bytes[8 ] | (iv_y_bytes[9 ] << 8) | (iv_y_bytes[10] << 16) | (iv_y_bytes[11] << 24));
  y_iv[3] = (iv_y_bytes[12] | (iv_y_bytes[13] << 8) | (iv_y_bytes[14] << 16) | (iv_y_bytes[15] << 24));
  y_iv[4] = (iv_y_bytes[16] | (iv_y_bytes[17] << 8) | (iv_y_bytes[18] << 16) | (iv_y_bytes[19] << 24));
  y_iv[5] = (iv_y_bytes[20] | (iv_y_bytes[21] << 8) | (iv_y_bytes[22] << 16) | (iv_y_bytes[23] << 24));
  y_iv[6] = (iv_y_bytes[24] | (iv_y_bytes[25] << 8) | (iv_y_bytes[26] << 16) | (iv_y_bytes[27] << 24));
  y_iv[7] = (iv_y_bytes[28] | (iv_y_bytes[29] << 8) | (iv_y_bytes[30] << 16) | (iv_y_bytes[31] << 24));

  printf("IV Y (256bit): %08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX\n", y_iv[0], y_iv[1], y_iv[2], y_iv[3], y_iv[4], y_iv[5], y_iv[6], y_iv[7]);

  uint8_t key_bytes[32]; memcpy (key_bytes, ctx->RoundKey, 32); uint32_t key[8];
  key[0] = (key_bytes[0 ] | (key_bytes[1 ] << 8) | (key_bytes[2 ] << 16) | (key_bytes[3 ] << 24));
  key[1] = (key_bytes[4 ] | (key_bytes[5 ] << 8) | (key_bytes[6 ] << 16) | (key_bytes[7 ] << 24));
  key[2] = (key_bytes[8 ] | (key_bytes[9 ] << 8) | (key_bytes[10] << 16) | (key_bytes[11] << 24));
  key[3] = (key_bytes[12] | (key_bytes[13] << 8) | (key_bytes[14] << 16) | (key_bytes[15] << 24));
  key[4] = (key_bytes[16] | (key_bytes[17] << 8) | (key_bytes[18] << 16) | (key_bytes[19] << 24));
  key[5] = (key_bytes[20] | (key_bytes[21] << 8) | (key_bytes[22] << 16) | (key_bytes[23] << 24));
  key[6] = (key_bytes[24] | (key_bytes[25] << 8) | (key_bytes[26] << 16) | (key_bytes[27] << 24));
  key[7] = (key_bytes[28] | (key_bytes[29] << 8) | (key_bytes[30] << 16) | (key_bytes[31] << 24));

  printf(" KEY (256bit): %08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX\n", key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]);
}
/*******************************************************************************************************/
uint64_t CSPRNG(void) { 
  CSPRNG_CNT++;
  sha3_context ctx;
  int i;
  uint8_t data[256];
  for (i = 0; i < 256; i = i + 8) { 
    uint64_t k = PRNG(); uint32_t x[2]; x[0] = (k >> 32); x[1] = (k & 0xFFFFFFFF);
    data[i  ] = (x[0] & 0x000000ff);
    data[i+1] = (x[0] & 0x0000ff00) >> 8;
    data[i+2] = (x[0] & 0x00ff0000) >> 16;
    data[i+3] = (x[0] & 0xff000000) >> 24;
    data[i+4] = (x[1] & 0x000000ff);
    data[i+5] = (x[1] & 0x0000ff00) >> 8;
    data[i+6] = (x[1] & 0x00ff0000) >> 16;
    data[i+7] = (x[1] & 0xff000000) >> 24;
  }
  const uint8_t *hash;
  sha3_Init256(&ctx);
  sha3_Update(&ctx,data, 256);  
  hash = sha3_Finalize(&ctx);
  uint64_t o;
  (o = (((uint64_t)((hash)[0] & 0xFF)) << 56) | (((uint64_t)((hash)[1] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[2] & 0xFF)) << 40) | (((uint64_t)((hash)[3] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[4] & 0xFF)) << 24) | (((uint64_t)((hash)[5] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[6] & 0xFF)) <<  8) | (((uint64_t)((hash)[7] & 0xFF))));
  
  return o;
}
/*******************************************************************************************************/
uint64_t IVCSPRNG(void) { 
  sha3_context ctx;
  int i;
  uint8_t data[256];
  for (i = 0; i < 256; i = i + 8) { 
    uint64_t k = IVPRNG(); uint32_t x[2]; x[0] = (k >> 32); x[1] = (k & 0xFFFFFFFF);
    data[i  ] = (x[0] & 0x000000ff);
    data[i+1] = (x[0] & 0x0000ff00) >> 8;
    data[i+2] = (x[0] & 0x00ff0000) >> 16;
    data[i+3] = (x[0] & 0xff000000) >> 24;
    data[i+4] = (x[1] & 0x000000ff);
    data[i+5] = (x[1] & 0x0000ff00) >> 8;
    data[i+6] = (x[1] & 0x00ff0000) >> 16;
    data[i+7] = (x[1] & 0xff000000) >> 24;
  }
  const uint8_t *hash;
  sha3_Init256(&ctx);
  sha3_Update(&ctx,data, 256);  
  hash = sha3_Finalize(&ctx);
  uint64_t o;
  (o = (((uint64_t)((hash)[0] & 0xFF)) << 56) | (((uint64_t)((hash)[1] & 0xFF)) << 48) | \
       (((uint64_t)((hash)[2] & 0xFF)) << 40) | (((uint64_t)((hash)[3] & 0xFF)) << 32) | \
       (((uint64_t)((hash)[4] & 0xFF)) << 24) | (((uint64_t)((hash)[5] & 0xFF)) << 16) | \
       (((uint64_t)((hash)[6] & 0xFF)) <<  8) | (((uint64_t)((hash)[7] & 0xFF))));
  
  return o;
}
/*******************************************************************************************************/
void dump_entropy(uint8_t *data,int len) {
  uint64_t i; 
  uint8_t byte;
  FILE *f;
  printf("\n\nDumping ciphertext.dat\n\n");
  f = fopen("ciphertext.dat", "wb"); 
  for (i=0; i<len; i++) {
    byte = data[i];
    fwrite(&byte, sizeof(byte), 1, f);
  }
  fclose(f);
}
/*******************************************************************************************************/
unsigned char lastblock(FILE *fp) {
  uint32_t prev=ftell(fp);
  fseek(fp, 0L, SEEK_END);
  uint32_t sz=ftell(fp);
  fseek(fp,prev,SEEK_SET);
  uint8_t size;
  size = ((sz - ((uint32_t)(sz/32)*32)) & 0xFF);
  if (size == 0) { size = 32; } 
  unsigned char byte = (unsigned char)size;
  return byte;
}
/*******************************************************************************************************/
size_t blocks(FILE *fp) {
  size_t prev=ftell(fp);
  fseek(fp, 0L, SEEK_END);
  size_t sz=ftell(fp);
  fseek(fp,prev,SEEK_SET);
  sz = (uint32_t)((sz/32)-2);
  return sz;
}
/*******************************************************************************************************/
void dumpcounters() {
  printf("\n\n  PRNG: %"PRIu64", CSPRNG: %"PRIu64"\n", PRNG_CNT, CSPRNG_CNT);
}
/*******************************************************************************************************/
void *urandom_open() { return fopen("/dev/urandom", "r"); }
void urandom_close(void *urandom) { fclose((FILE*)urandom); }
int urandom_read(void *urandom, unsigned char *buffer, size_t size) { return fread(buffer, 1, size, (FILE*)urandom); }
/*******************************************************************************************************/
void dump_key() {
  sha3_context ctx;
  int i;
  uint8_t i_seed[8192];
  uint8_t o_seed[8192];
  void *urand;
  size_t bytes_read;  
  const uint8_t *hash;
  if ((urand = urandom_open()) == NULL) { 
    perror("Error open /dev/urandom:"); return; 
  }
  for (i = 0; i < 8200; i = i + 200) {
    memset(i_seed, 0, 8192);    
    if ((bytes_read = urandom_read(urand, i_seed, 8192)) != 8192) {
      fprintf(stderr, "Error: Couldn't read from urandom : %u\n", (unsigned) bytes_read);
      urandom_close(urand);
      return;
    }
    sha3_Init256(&ctx);
    sha3_Update(&ctx, i_seed, 8192);
    hash = sha3_Finalize(&ctx);
    if (i == 8000) {
      memcpy(o_seed+i, hash, 192);
    } else {
      memcpy(o_seed+i, hash, 200);
    }
  }
  urandom_close(urand);
  print_hex(o_seed, 8192);
  uint8_t byte;
  FILE *f;
  printf("\n\nDumping key.dat\n\n");
  f = fopen("key.dat", "wb"); 
  for (i=0; i<8192; i++) {
    byte = o_seed[i];
    fwrite(&byte, sizeof(byte), 1, f);
  }
  fclose(f);
}
/*******************************************************************************************************/
int main(int argc, char *argv[]) {
  FILE *keyfp = NULL;  
  FILE *infp = NULL;
  FILE *outfp = NULL;
  struct PRINCESS_ctx ctx;  
  int rc=0;
  size_t bytes_read;
  unsigned char buffer[32];
  unsigned char keyfile[8192];  
  while ((rc = getopt(argc, argv, "ked")) != -1) {
    switch (rc) {
      case 'k':
        dump_key();
        break;
      case 'e':
        keyfp = fopen("key.dat", "r");
        memset(keyfile, 0, 8192);    
        if ((bytes_read = fread(keyfile, 1, 8192, keyfp)) != 8192) {
          fprintf(stderr, "Error: Couldn't read from key.dat : %u\n", (unsigned) bytes_read);
          fclose(keyfp);
          return;
        }
        PRINCESS_init_preboot(&ctx,keyfile,8192,0); ctx.mode = 0;
        infp = fopen("test.dat", "r");
        outfp = fopen("encrypted.dat", "w");        
        dump_keys(&ctx);
        unsigned char byte[1];
        byte[0] = lastblock(infp);
        fwrite(byte, 1, 1, outfp);
        uint8_t IV_X_A[32]; 
        memcpy (IV_X_A, ctx.IV_X, 32); 
        HeadCrypt(IV_X_A); 
        fwrite(IV_X_A, 1, 32, outfp);
        uint8_t IV_Y_A[32]; 
        memcpy (IV_Y_A, ctx.IV_Y, 32); 
        HeadCrypt(IV_Y_A); 
        fwrite(IV_Y_A, 1, 32, outfp);
        while ((bytes_read = fread(buffer, 1, 32, infp)) > 0) {
          PRINCESS_MYST_encrypt_buffer(&ctx, buffer, 32);
          fwrite(buffer, 1, 32, outfp);
          memset(buffer, 0x00, 32);
        }
        fflush(outfp); fclose(infp); fclose(outfp); fclose(keyfp);
        dumpcounters();
        printf("\n\nENC DONE\n");
        break;
      case 'd':
        keyfp = fopen("key.dat", "r");
        memset(keyfile, 0, 8192);    
        if ((bytes_read = fread(keyfile, 1, 8192, keyfp)) != 8192) {
          fprintf(stderr, "Error: Couldn't read from key.dat : %u\n", (unsigned) bytes_read);
          fclose(keyfp);
          return;
        }      
        PRINCESS_init_preboot(&ctx,keyfile,8192,1); ctx.mode = 0;     
        infp = fopen("encrypted.dat", "r");
        outfp = fopen("decrypted.dat", "w");
        memset(buffer, 0x00, 32);
        bytes_read = fread(buffer, 1, 1, infp);
        size_t last = (size_t)buffer[0];
        printf("LAST BLOCK SIZE: %d\n",last);
        size_t blocks_cnt = blocks(infp);
        memset(buffer, 0x00, 32);
        bytes_read = fread(buffer, 1, 32, infp);
        uint8_t IV_X_BYTES[32]; memcpy (IV_X_BYTES, buffer, 32);
        HeadCrypt(IV_X_BYTES);
        memcpy (ctx.IV_X, IV_X_BYTES, 2 * PRINCESS_BLOCKLEN);        
        memset(buffer, 0x00, 32);
        bytes_read = fread(buffer, 1, 32, infp);
        uint8_t IV_Y_BYTES[32]; memcpy (IV_Y_BYTES, buffer, 32);
        HeadCrypt(IV_Y_BYTES);
        memcpy (ctx.IV_Y, IV_Y_BYTES, 2 * PRINCESS_BLOCKLEN); 
        dump_keys(&ctx);         
        while ((bytes_read = fread(buffer, 1, 32, infp)) > 0) {
          PRINCESS_MYST_decrypt_buffer(&ctx, buffer, 32);
          if (blocks_cnt <= 1) {
            fwrite(buffer, 1, last, outfp);
          } else {
            fwrite(buffer, 1, 32, outfp);
          }
          memset(buffer, 0x00, 32);
          --blocks_cnt;
        }
        fflush(outfp); fclose(infp); fclose(outfp); fclose(keyfp);
        dumpcounters();
        printf("\n\nDEC DONE\n");
        break; 
      default:
        fprintf(stderr, "Error: Unknown option '%c'\n", rc);
        return 0;
    }
  }
}
/*******************************************************************************************************/
// EOF
