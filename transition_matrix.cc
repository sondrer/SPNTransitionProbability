/* rijndael-alg-ref.c   v2.2   March 2002
 * Reference ANSI C code
 * authors: Paulo Barreto
 *          Vincent Rijmen
 *
 * This code is placed in the public domain.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <NTL/ZZ.h>
#include "rijndael-alg-ref.h"
#include <stdio.h>
#include <stdlib.h>
#include <NTL/RR.h>
#define SC	((BC - 4) >> 1)
#include <fstream>
#include "boxes-ref.dat"
#include <NTL/mat_ZZ.h>
#include <NTL/mat_RR.h>
#include <set>
#include <unordered_set>
#include <iterator>
#include <list>
#include <map>
NTL::RR bin[5];
static int prec = 300;
NTL::RR Q32;
NTL::RR pow_list[5];
NTL::mat_RR Q1;

using namespace std;
static word8 shifts[3][4][2] = {
  {{0, 0},
   {1, 3},
   {2, 2},
   {3, 1}},
   
  {{0, 0},
   {1, 5},
   {2, 4},
   {3, 3}},
   
  {{0, 0},
   {1, 7},
   {3, 5},
   {4, 4}}
}; 



word8 mul(word8 a, word8 b) {
   /* multiply two elements of GF(2^m)
    * needed for MixColumn and InvMixColumn
    */
	if (a && b) return Alogtable[(Logtable[a] + Logtable[b])%255];
	else return 0;
}


void AddRoundKey(word8 a[4][MAXBC], word8 rk[4][MAXBC], word8 BC) {
	/* Exor corresponding text input and round key input bytes
	 */
	int i, j;
	
	for(i = 0; i < 4; i++)
   		for(j = 0; j < BC; j++) {
        a[i][j] ^= (rk[i][j]);
      }
}

void ShiftRows(word8 a[4][MAXBC], word8 d, word8 BC) {
	/* Row 0 remains unchanged
	 * The other three rows are shifted a variable amount
	 */
	word8 tmp[MAXBC];
	int i, j;
	
	for(i = 1; i < 4; i++) {
		for(j = 0; j < BC; j++) 
                	tmp[j] = a[i][(j + shifts[SC][i][d]) % BC];
		for(j = 0; j < BC; j++) a[i][j] = tmp[j];
	}
}

void Substitution(word8 a[4][MAXBC], word8 box[256], word8 BC) {
	/* Replace every byte of the input by the byte at that place
	 * in the nonlinear S-box.
         * This routine implements SubBytes and InvSubBytes
	 */
	int i, j;
	
	for(i = 0; i < 4; i++)
		for(j = 0; j < BC; j++) a[i][j] = box[a[i][j]] ;
}
   
void MixColumns(word8 a[4][MAXBC], word8 BC) {
        /* Mix the four bytes of every column in a linear way
	 */
	word8 b[4][MAXBC];
	int i, j;
		
	for(j = 0; j < BC; j++)
		for(i = 0; i < 4; i++)
			b[i][j] = mul(2,a[i][j])
				^ mul(3,a[(i + 1) % 4][j])
				^ a[(i + 2) % 4][j]
				^ a[(i + 3) % 4][j];
	for(i = 0; i < 4; i++)
		for(j = 0; j < BC; j++) a[i][j] = b[i][j];
}

void MixColumnsX(word8 a[4]) {
        /* Mix the four bytes of every column in a linear way
   */
  word8 b[4];
  int i, j;
    
  for(j = 0; j < 1; j++)
    for(i = 0; i < 4; i++)
      b[i] = mul(2,a[i])
        ^ mul(3,a[(i + 1) % 4])
        ^ a[(i + 2) % 4]
        ^ a[(i + 3) % 4];
  for(i = 0; i < 4; i++)
      a[i] = b[i];
}

void InvMixColumns(word8 a[4][MAXBC], word8 BC) {
        /* Mix the four bytes of every column in a linear way
	 * This is the opposite operation of Mixcolumns
	 */
	word8 b[4][MAXBC];
	int i, j;
	
	for(j = 0; j < BC; j++)
	for(i = 0; i < 4; i++)             
		b[i][j] = mul(0xe,a[i][j])
			^ mul(0xb,a[(i + 1) % 4][j])                 
			^ mul(0xd,a[(i + 2) % 4][j])
			^ mul(0x9,a[(i + 3) % 4][j]);                        
	for(i = 0; i < 4; i++)
		for(j = 0; j < BC; j++) a[i][j] = b[i][j];
}

int rijndaelKeySched (word8 k[4][MAXKC], int keyBits, int blockBits, 	word8 W[MAXROUNDS+1][4][MAXBC]) {
	/* Calculate the necessary round keys
	 * The number of calculations depends on keyBits and blockBits
	 */
	int KC, BC, ROUNDS;
	int i, j, t, rconpointer = 0;
	word8 tk[4][MAXKC];   

	switch (keyBits) {
	case 128: KC = 4; break;
	case 192: KC = 6; break;
	case 256: KC = 8; break;
	default : return (-1);
	}

	switch (blockBits) {
	case 128: BC = 4; break;
	case 192: BC = 6; break;
	case 256: BC = 8; break;
	default : return (-2);
	}

	switch (keyBits >= blockBits ? keyBits : blockBits) {
	case 128: ROUNDS = 10; break;
	case 192: ROUNDS = 12; break;
	case 256: ROUNDS = 14; break;
	default : return (-3); /* this cannot happen */
	}

	
	for(j = 0; j < KC; j++)
		for(i = 0; i < 4; i++)
			tk[i][j] = k[i][j];
	t = 0;
	/* copy values into round key array */
	for(j = 0; (j < KC) && (t < (ROUNDS+1)*BC); j++, t++)
		for(i = 0; i < 4; i++) W[t / BC][i][t % BC] = tk[i][j];
		
	while (t < (ROUNDS+1)*BC) { 
        	/* while not enough round key material calculated */
		/* calculate new values */
		for(i = 0; i < 4; i++)
			tk[i][0] ^= S[tk[(i+1)%4][KC-1]];
		tk[0][0] ^= rcon[rconpointer++];

		if (KC != 8)
			for(j = 1; j < KC; j++)
				for(i = 0; i < 4; i++) tk[i][j] ^= tk[i][j-1];
		else {
			for(j = 1; j < KC/2; j++)
				for(i = 0; i < 4; i++) tk[i][j] ^= tk[i][j-1];
			for(i = 0; i < 4; i++) 
                        	tk[i][KC/2] ^= S[tk[i][KC/2 - 1]];
			for(j = KC/2 + 1; j < KC; j++)
				for(i = 0; i < 4; i++) tk[i][j] ^= tk[i][j-1];
	}
	/* copy values into round key array */
	for(j = 0; (j < KC) && (t < (ROUNDS+1)*BC); j++, t++)
		for(i = 0; i < 4; i++) W[t / BC][i][t % BC] = tk[i][j];
	}		

	return 0;
}
/*
The layer in front of SLS. Used for verifying that right pair was indeed found.
*/
int Q(word8 a[4][MAXBC],word8 rk[MAXROUNDS+1][4][MAXBC]){
  int BC = 4;
  AddRoundKey(a,rk[0],BC);

  //ShiftRows(a,0,BC);

  Substitution(a,S,BC);
  MixColumns(a,BC);
  AddRoundKey(a,rk[1],BC);
  ShiftRows(a,0,BC);
  return 0;
}

/* Everything above here is code related to AES made by Barreto and Rijmen */

int randomInRange(int min, int max){

      int range = max;
    int a, b, c, d;

    a = rand() % range;
    b = rand() % range;
    c = rand() % range;
    d = (a*b) % range;
    d = (d+c) % range;
    if(d < 0)
      { return (range+d);}
    else{
       return (d)%range;
    }

}
/*
Change to mod 15 if k=4
*/
word8 randomByte(){
    return (word8) randomInRange(0, 255);
}

void PrintXOR(word8 block1[4][MAXBC], word8 block2[4][MAXBC])
{
  int i, j;
  for(i = 0; i < 4; i++) {
    for(j = 0; j < 4; j++) {
      printf("%2X", block1[j][i]^block2[j][i]);
    } printf(" ");
  }
  printf("\n");
}

void Print(word8 block1[4][MAXBC])
{
  int i, j;

 
  for(i = 0; i < 4; i++) {
    for(j = 0; j < 4; j++) {
      printf("%2X", block1[j][i]);
    } printf(" ");
  }
  printf("\n");
}


void Encrypt (word8 a[4][MAXBC],word8 rk[MAXROUNDS+1][4][MAXBC], int rounds)
/* Encrypt only a certain number of rounds.
 * Only used in the Intermediate Value Known Answer Test.
 */
{
  int r, BC;
  BC = 4;
  AddRoundKey(a,rk[0],BC);
 
  for(r = 0; r < rounds; r++) {
    Substitution(a,S,BC);
    ShiftRows(a,0,BC);
    MixColumns(a,BC);
    AddRoundKey(a,rk[r+1],BC);
  }

}   


int Decrypt (word8 a[4][MAXBC], word8 rk[MAXROUNDS+1][4][MAXBC], int rounds)

{
  int r, BC;
  BC = 4;


  for(r = 0; r < rounds; r++) {
    AddRoundKey(a,rk[rounds-r],BC);
    InvMixColumns(a,BC);  
    ShiftRows(a,1,BC);
    Substitution(a,Si,BC);   
  }
 
  AddRoundKey(a,rk[0],BC);
  
  return 0;
}


int weight(word8 s[4][4],int k){
  int w = 0;
  for (int j=0; j < 4; j++ ){
    if (s[j][k] != 0)
      w+=1;
  }
  return w;
}

int weight_word(int s){
  int w  = 0;
  for (int j=0; j < 4; j++ ){
    if (((s>>j)&1) == 1){
      w+=1;
    }
  }
  return w;
}

int hweight(int x){
 int t;
  t = 0;
  for(int j=0; j< 4; j++){
    if ((x>>j)&1){
      t+=1;
    }
  }
  return t; 
}

void weight_pattern(int wpattern[4], int p1, int x){

   word8 S1[4][4];
   int t_ind = 0;
    for(int i=0; i < 4; i++){
      if ((x>>i)&1){
      for(int j=0; j < 4; j++){
          S1[j][i] = (p1>>(4*t_ind+j))&1;
      } 
      t_ind++;
    }
   }
   ShiftRows(S1,0,4);


    for(int i=0; i <4; i++){
       wpattern[i] = weight(S1,i);
    }

}
void weight_pattern2(int wpattern0[4], int wpattern1[4], int p1){
   word8 S1[4][4];

    for(int i=0; i < 4; i++){
      for(int j=0; j < 4; j++)
          S1[j][i] = (p1 >> (4*i+j))&1;
   }
   for(int i=0; i< 4; i++)
    wpattern0[i] = weight(S1,i);

   ShiftRows(S1,0,4);

    for(int i=0; i <4; i++){
       wpattern1[i] = weight(S1,i);
    }
}
void weight_pattern3(int wpattern[4],int p1){
   word8 S1[4][4];
   int r; 
   for(int j=0; j< 4; j++){
    r = floor(p1/pow(5,3-j));
    p1 = p1 - r*pow(5,3-j);
    wpattern[3-j] = r;
   }


}

void weight_pattern_inverse(int wpattern[4], int p1, int x){

   word8 S1[4][4];
    int t_ind = 0;
    for(int i=0; i < 4; i++){
      if ((x>>i)&1){
      for(int j=0; j < 4; j++){
          S1[j][i] = (p1>>(4*t_ind+j))&1;
      }
      t_ind++;
      }  
   }
   ShiftRows(S1,1,4);


    for(int i=0; i <4; i++){
       wpattern[i] = weight(S1,i);
    }

}
int compute_index(int wpattern[4]){
  int I = 0;
  for(int i=0; i < 4; i++){
    I += pow(5,i)*wpattern[i];
  }
  return I;
}

NTL::RR number_of_patterns2(int wpattern[4]){
  NTL::RR N;
  N = 1;
  for(int i=0; i < 4; i++){
    N = N*bin[wpattern[i]];
  }
  return N;

}

int number_of_patterns(int x){
  int N =1;
  for(int i=0; i < 4; i++){
    if ((x>>i)&1){
      N = N*15;
    }
  }
  return N;

}
/*
 
*/
NTL::RR P(int I,int J){

   //for(int I=1; I < 2; I++){

    NTL::RR N;
    N.SetPrecision(prec);
    N = 1;       
    for(int i=0; i < 4; i++){
      if ((I>>i)&1){
        N = N*(Q32-1);
      }
    }
    //N = 4*255;
  
      NTL::RR paes;
      paes = 0;
      paes.SetPrecision(prec); 
      int first_round = 0;
      for(int i=1; i < 625;i++){
        int wpatternx[4];
        weight_pattern3(wpatternx,i);      
        int correctx = 1;     
        for(int k=0; k < 4;k++){
          if(((I>>k)&1) == 0 && wpatternx[k] > 0)
            correctx = 0;
          if(((I>>k)&1) == 1 && wpatternx[k] == 0)
            correctx = 0;
                  
        }

       if (correctx == 1){

        for(int j=0; j < 625; j++){
          int wpatterny[4];
          weight_pattern3(wpatterny,j); 
          int correcty = 1;
                   
          for(int k=0; k < 4;k++){

            if(((J>>k)&1) == 0 && wpatterny[k] > 0){
              correcty = 0;
            }
            if(((J>>k)&1) == 1 && wpatterny[k] == 0){
              correcty = 0;
            }                  
          }  
                  
          if (correcty == 1){
            
            NTL::RR q1;
            q1.SetPrecision(prec);
            q1 = 1;
            for(int z=0; z< 4;z++){
              q1 = q1*bin[wpatternx[z]]*pow_list[wpatternx[z]];
             // cout << "bin(4,"<< wpatternx[z]<<" x (2^8-1)^"<<wpatternx[z]<<endl;
            }

            //cout << q1<<endl;
            
            paes += (q1)*Q1[i][j];
            
          }
        }
        first_round = 1;
      }
    }
    return paes;
}
/*
  Computes transition probabilty matrices form MC and SR layers, and construct r round transition probability 
  matrix by multiplying these togehter enough times.  
*/

/*

  Computing the weight transition probability (WTP) matrix for AES, which may be viewed as a 
  extended weight distribution matrix for a (32,16) code over GF(2^8).

  An exchange set WTP is considered. It combines a 1 round exchange transition probability with the wtp. 
  Thus, let TX[I,J] denote the probability that exchanging 


*/
int main(){

  Q32 = 4294967296;
  /* Correct handling of precision is important and may cause root to errors. */
  Q1.SetDims(625,625);
  Q1[0][0].SetPrecision(prec);
  Q1[0][0].SetOutputPrecision(prec);
  
  NTL::RR blist[5];
  blist[0] = 1;
  blist[1] = 4;
  blist[2] = 6;
  blist[3] = 4;
  blist[4] = 1; 

  int Qw[5] = {0,1,3,7,15};

  static NTL::mat_RR TSR;//[625][625];
  static NTL::mat_RR TMC;//[625][625];
  TSR.SetDims(625,625);
  TMC.SetDims(625,625);

  TSR[0][0].SetPrecision(prec);
  TSR[0][0].SetOutputPrecision(prec);

  TMC[0][0].SetPrecision(prec);
  TMC[0][0].SetOutputPrecision(prec);


  NTL::RR one;
  one.SetPrecision(prec);
  one.SetOutputPrecision(prec);
  one = 1;
  // Setting precision on first element defines precision on all elements in table
  pow_list[0].SetPrecision(prec);
  pow_list[0] = 1;
  pow_list[1] = 255;
  pow_list[2] = 65025;
  pow_list[3] = 16581375;
  pow_list[4] = 4228250625;

  bin[0].SetPrecision(prec);
  bin[0] =1;
  bin[1] =4;
  bin[2] =6;
  bin[3] =4;
  bin[4] =1;
  int BC = 4;
  sranddev();
 
  int detected = 0;
  int min = 100;

  /* Read the MDS weight distribution from file */
  NTL::ZZ Z_ZZ[16][16];
  std::fstream fil;
  fil.open("Z-Table.bin",std::fstream::in);
  for(int i=0; i< 16; i++){
    for(int j=0; j< 16; j++)
      fil >> Z_ZZ[i][j];
  }
  fil.close();
  std::cout<<std::endl;

  NTL::ZZ Q;
  Q = 0;

  // Convert transition table to RR 
  NTL::RR Z[16][16];

  for(int i=0; i < 16; i++){
    NTL::RR res;
    res  =0 ;
    for(int j=0; j < 16; j++){
      conv(Z[i][j],Z_ZZ[i][j]);
    }
  }

  /*
    Compute T_SR
    Compute L_SR 
  */
  /*
    Z_Table is the transition probability matrix for the MixColumns matrix 
    
  */
  NTL::mat_RR Z_Table;
  Z_Table.SetDims(25,25);
  //Z_Table[0][0].SetPrecision(prec);
  //Z_Table[0][0].SetPrecision(1000);
  for(int i=0; i < 5; i++){
    for(int j=0; j < 5; j++){
      //Z_Table[i][j].SetPrecision(1000);
      Z_Table[i][j] = Z[Qw[i]][Qw[j]]/(pow_list[i]);
    }
  }
      std::cout<< "Compute TSR"<<std::endl;

  /*

    The transition probabilities for the SR layer is straight-forward. 
  */
  for(int p1=0; p1 < 65536; p1++){
        int I = 0;
        int J = 0;
        int wpattern0[4];
        int wpattern1[4];

        /* This function is the main one here. */
        weight_pattern2(wpattern0,wpattern1,p1);

        I = compute_index(wpattern0);
        J = compute_index(wpattern1);
        
        int i1;
        int i2;
        int i3;
        int i4;

        int j1;
        int j2;
        int j3;
        int j4;

        i1 = wpattern0[0];
        i2 = wpattern0[1];
        i3 = wpattern0[2];
        i4 = wpattern0[3];

        j1 = wpattern1[0];
        j2 = wpattern1[1];
        j3 = wpattern1[2];
        j4 = wpattern1[3];

        NTL::RR M;
        M=1;
        for(int i=0; i < 4; i++){                
            M = M*bin[wpattern0[i]];
        }
        TSR[I][J] += 1/M; 
  }
 
    std::cout<< "Compute TMC"<<std::endl;

  /*

  Compute a 625 x 625 transition matrix T_MC where indices are in base-5, e.g. an integer 0<= I < 625 can be written as
  I= i0 + i1*5 + i2*5^2 + i3*5^3 where (i0,i1,i2,i3) is such that there are i_j active bytes in the j'th column 
  with respect to the SuperBox representation (i.e. the first and last linear layers are omitted so that we 
  can work only with columns)

  T_MC is populated by going through all possible 625^2 combinations I,J and simply computing
  T_MC[i0+i1*5+i3*5^2+i4*5^3][j0+j1*5+j3*5^2+j4*5^3] = 
        Pr(wt pattern (j0,j1,j2,h3) out | weight pattern (i0,i1,i2,i3) in) = MDS-transition probabilities. 
  */
  for(int w1=0; w1 < 5; w1++){
    for(int w2=0; w2 < 5; w2++){  
      for(int w3=0; w3 < 5; w3++){
        for(int w4=0; w4 < 5; w4++){

          int wpattern0[4] = {w1,w2,w3,w4};
          int I = 0;
          I = compute_index(wpattern0);

          for(int v1=0; v1 < 5; v1++){ 
            for(int v2=0; v2 < 5; v2++){  
              for(int v3=0; v3 < 5; v3++){
                for(int v4=0; v4 < 5; v4++){

                  int wpattern1[4] = {v1,v2,v3,v4};
                  int J=0;
                  J = compute_index(wpattern1);
                  NTL::RR q;
                  q = 1;
                  /*
                    Product of 
                  */
                  /*
                      Z_Table[i][j] is the transition probability for a single MixColumns
                  */
                  for(int i=0; i < 4; i++){                
                    q *= Z_Table[wpattern0[i]][wpattern1[i]];
                    
                  }
               
          
                
                TMC[I][J] = (bin[v1]*bin[v2]*bin[v3]*bin[v4])*q;
                }
              } 
            }
          }
        }
      }
    }
  }

  /*
    Compute transition probability matrix Q1 formed by iterating TMC and TSR. 
  */

 

  std::cout<<"Compute product of matrices (currently takes the most time... < minute-ish?) " << std::endl;
  NTL::mat_RR Q2;
  Q2.SetDims(625,625);
  Q1[0][0].SetPrecision(prec);
  Q2[0][0].SetOutputPrecision(prec);
  /*
  Note that we start after (MC SR MC SR MC) = 4 rounds, so we need to start with SR
  */
  Q1 = TMC*TSR*TMC*TSR*TMC*TSR*TMC;
  
  NTL::RR Total;

  /*
  Q1[4][r] is the probability that two plaintexts with difference in D_0 + non-zero difference in all bytes in D_0
  result in a pair of ciphertexts with weight-pattern given by (u_0,u_1,u_2,u_3) where 
  r = u_0+u_1*5 + u_2*5^2 + u_3*5^3. 
  We restrict the below sum to all outputs where the first word has weight 0 (v4=0) corresponding to the case that
  the output is equal in M_0. 
  */

  NTL::RR N;
  NTL::RR part;
  part = 0;
  N = 0;
  NTL::RR MAXX;
  NTL::RR MAXX2;
  MAXX = 0;
  MAXX2 = 0;
  NTL::RR prand;
  prand.SetPrecision(prec);
  NTL::RR paes;

  paes.SetPrecision(prec);
  NTL::vec_RR pvec;

  pvec[0].SetPrecision(prec);

  pvec.SetLength(4);

  prand = 0;
  paes = 0;
  NTL::vec_RR uvec;
  uvec.SetLength(625);
  uvec[0].SetPrecision(prec);


  for(int u=1; u < 5; u++){
      uvec[u]=bin[u]*pow_list[u]/(Q32-1);
  }
  uvec = uvec*Q1;
  NTL::RR su;
  su = 0;
  NTL::vec_RR z;
  z.SetLength(625);
  NTL::RR maxc;
  NTL::RR minc;
  maxc = -1;
  minc = 1;
  for(int v1=0; v1 < 5; v1++){
    for(int v2=0; v2 < 5; v2++){
        for(int v3=0; v3 < 5; v3++){
          for(int v4=0; v4 < 5; v4++){
            

            if (v1 == 0 ||v2 == 0 ||v3 == 0 ||v4 == 0){
              prand += bin[v1]*pow_list[v1]*bin[v2]*pow_list[v2]*bin[v3]*pow_list[v3]*bin[v4]*pow_list[v4]/(Q32*Q32*Q32*Q32);
              paes += uvec[v1+v2*5+v3*pow(5,2)+v4*pow(5,3)];
            }
        }
      }
    }
  }
  cout << paes - prand<<endl;
  exit(0);
  NTL::RR maxx;
  maxx = 0; 
  int wpx[4];
  int wpy[4];
  for(int i=1; i < 625; i++){
    weight_pattern3(wpx,i);    

    for(int j=1; j < i; j++){
       weight_pattern3(wpy,j);    

      if (abs(z[i]-z[j]) > maxx){
        for(int t=0; t < 4; t++){
          cout << wpx[t]<<" ";
        }
        cout<<"  vs  ";
        for(int t=0; t < 4; t++){
          cout << wpy[t]<<" ";
        }
        cout<<endl;
        maxx = abs(z[i]-z[j]);
        cout << prand-z[i]<<endl;
        cout << prand-z[j]<<endl;
        cout<< maxx<<endl;
        cout<<endl;
      }
    }
  }
    

  /*
  cout << paes<<endl;
  
  for(int i=0; i< 4; i++){
    cout << abs(pvec[i]-1/Q32)<<endl;
    cout << abs(pvec[i]-prand)<<endl;
    cout<<" "<<endl;
  }

  cout<<endl;
  cout << "difference"<<endl;
  cout << (paes-prand)<<endl;
  cout<< "Rand"<<endl;
  cout<< prand<<endl;
  cout<< "AES"<<endl;
  cout<<paes<<endl;
  */
  
  /*

  NTL::RR max;
  max = 0;
  NTL::RR max2;
  max2 = 0;
  int wp1[4];
  int wp2[4];
      
  int tmp_max =0 ;
  for(int i=1; i < 625; i++){
    if ((N-v[i]) > max2){
        max2 = (N-v[i]);
        tmp_max = i;
      }

    if ((v[i] - N) > max2){
      max2 = (v[i]-N);
      tmp_max = i;
    }
    
    weight_pattern3(wp1,i);  
    for(int j=1; j < i; j++){
      if (abs(v[i]-v[j]) > max){
        weight_pattern3(wp2,j);  
        max = abs(v[i]-v[j]);
 */
      



  

}