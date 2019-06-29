#ifndef __RIJNDAEL_ALG_H
#define __RIJNDAEL_ALG_H

/* rijndael-alg-ref.h   v2.0   August '99
 * Reference ANSI C code
 * authors: Paulo Barreto
 *          Vincent Rijmen, K.U.Leuven
 */

#define MAXBC                (128/32)
#define MAXKC                (128/32)
#define MAXROUNDS            10

typedef unsigned char word8;
typedef unsigned short word16;
typedef unsigned long word32;


int rijndaelKeySched(word8 k[4][MAXKC], int keyBits, int blockBits,
                     word8 rk[MAXROUNDS + 1][4][MAXBC]);

int rijndaelEncrypt(word8 a[4][MAXBC], int keyBits, int blockBits,
                    word8 rk[MAXROUNDS + 1][4][MAXBC]);

int rijndaelEncryptRound(word8 a[4][MAXBC], int keyBits, int blockBits,
                         word8 rk[MAXROUNDS + 1][4][MAXBC], int rounds);

int rijndaelDecrypt(word8 a[4][MAXBC], int keyBits, int blockBits,
                    word8 rk[MAXROUNDS + 1][4][MAXBC]);

int rijndaelDecryptRound(word8 a[4][MAXBC], int keyBits, int blockBits,
                         word8 rk[MAXROUNDS + 1][4][MAXBC], int rounds);

#endif /* __RIJNDAEL_ALG_H */
