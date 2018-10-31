#include "aes.h"
#include "block.h"

//void PRG(AES_KEY *key, block input, block** output, int** bits, int start, int len);

static int getbit(int x, int n, int b);

void GEN(AES_KEY *key, int alpha, int n, unsigned char** k0, unsigned char **k1);

void GEN_(AES_KEY *key, int alpha, int n, unsigned char** k0, unsigned char **k1);


block EVAL(AES_KEY *key, unsigned char* k, int x);

block* EVALFULL(AES_KEY *key, unsigned char* k);

block* EVALFULL_(AES_KEY *key, unsigned char* k);