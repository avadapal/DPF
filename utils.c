#include <stdio.h>
#include <string.h>
#include "utils.h"
  
void PRG2(AES_KEY *key, block input, block** output, int** bits, int start, int len){
	input = dpf_set_lsb_zero(input);

	block stash[len];
	for (int i = 0; i < len; ++i) stash[i] = dpf_xor_int(input, start+i);

	AES_ecb_encrypt_blks(stash, len, key);

	for (int i = 0; i < len; ++i)
	{
		stash[i] = dpf_xor(stash[i], dpf_xor_int(input, start+i));
		*bits[i] = dpf_lsb(stash[i]);
		*output[i] = dpf_set_lsb_zero(stash[i]);
	}
} 

void PRG(AES_KEY * key, block input, block * output1, block * output2, int * bit1, int * bit2, int start, int len) 
{
	int ** bits = (int**)malloc(2*sizeof(int*));
	block ** output;
	output = (block**) malloc (2 * sizeof(block*));
	output[0] = output1;
	output[1] = output2;
	bits[0] = bit1;
	bits[1] = bit2;

	PRG2(key, input, output, bits, 0, 2);

	free(output);
	free(bits);
}


// Here tlNew, tR_New, scW are the new CWs
void compute_next_level(int i, AES_KEY *key, int alpha, int n, unsigned char** k0, 
			unsigned char **k1, block sL, block sR, int tL, int tR, 
			block* new_sL, block* new_sR, int* new_tL, int* new_tR,
			block* sCW, int* tCWL, int* tCWR){
	

		printf("\n Compute Next Level \n");
		
		int maxlayer = n;
	
		//block s[maxlayer + 1][2];
        	
        	block sCW_;
        	int tCW[2];

        	
        	block s0[2], s1[2]; // 0=L,1=R
        	#define LEFT 0
        	#define RIGHT 1
	        int t0[2], t1[2];

		/*
		 PRG takes in as input sL (or SR) and expands it
		 PRG(s) = SL||tL||sR||tR
		 Basically, takes in a radom string of length l and outputs, (2l + 2)-length random string	
		*/
                		
		PRG(key, sL, &s0[LEFT], &s0[RIGHT], &t0[LEFT], &t0[RIGHT], 0, 2);
		//PRG(key, s[i-1][0], &s0[LEFT], &s0[RIGHT], &t0[LEFT], &t0[RIGHT]);
		
		PRG(key, sR, &s1[LEFT], &s1[RIGHT], &t1[LEFT], &t1[RIGHT], 0, 2);		
	        //PRG(key, s[i-1][1], &s1[LEFT], &s1[RIGHT], &t1[LEFT], &t1[RIGHT]);

                int keep, lose;
                int alphabit = getbit(alpha, n, i);
		printf("alphabit = %d \n", alphabit); 
                if(alphabit == 0){
                        keep = LEFT;
                        lose = RIGHT;
                }else{
                        keep = RIGHT;
                        lose = LEFT;
                }

                *sCW = dpf_xor(s0[lose], s1[lose]);

                *tCWL = t0[LEFT] ^ t1[LEFT] ^ alphabit ^ 1;
                *tCWR = t0[RIGHT] ^ t1[RIGHT] ^ alphabit;
				
		sCW_ = dpf_xor(s0[lose], s1[lose]);

		tCW[LEFT] = t0[LEFT] ^ t1[LEFT] ^ alphabit ^ 1;
		tCW[RIGHT] = t0[RIGHT] ^ t1[RIGHT] ^ alphabit;
		
		if(tL == 1){
			*new_sL = dpf_xor(s0[keep], sCW_);
			*new_tL = t0[keep] ^ tCW[keep];
		}else{
			*new_sL = s0[keep];
			*new_tL = t0[keep];
		}

		if(tR == 1){
			*new_sR = dpf_xor(s1[keep], sCW_);
			*new_tR = t1[keep] ^ tCW[keep];
		}else{
			*new_sR = s1[keep];
			*new_tR = t1[keep];
		}
	
	
}


void compute_next_bit_leaf(AES_KEY *key, int alpha, block sL, block sR, int k, block* CW){
	printf("\ncompute next bit leaf\n");
	block s0[2], s1[2]; // 0=L,1=R
	#define LEFT 0
        #define RIGHT 1
	int t0[2], t1[2];
	
	int i;
	
	for(i = 0; i < k; i++){
	PRG(key, sL, &s0[LEFT], &s0[RIGHT], &t0[LEFT], &t0[RIGHT], i * 2, 2);
	//PRG(key, s[i-1][0], &s0[LEFT], &s0[RIGHT], &t0[LEFT], &t0[RIGHT]);
	PRG(key, sR, &s1[LEFT], &s1[RIGHT], &t1[LEFT], &t1[RIGHT], i * 2, 2);
	
		
	CW[i] = dpf_zero_block();
	CW[i] = dpf_reverse_lsb(CW[i]);

	char shift = (alpha) & 127;
	
	if(shift & 64){
		CW[i] = dpf_left_shirt(CW[i], 64);
	}
	if(shift & 32){
		CW[i] = dpf_left_shirt(CW[i], 32);
	}
	if(shift & 16){
		CW[i] = dpf_left_shirt(CW[i], 16);
	}
	if(shift & 8){
		CW[i] = dpf_left_shirt(CW[i], 8);
	}
	if(shift & 4){
		CW[i] = dpf_left_shirt(CW[i], 4);
	}
	if(shift & 2){
		CW[i] = dpf_left_shirt(CW[i], 2);
	}
	if(shift & 1){
		CW[i] = dpf_left_shirt(CW[i], 1);
	}

	CW[i] = dpf_reverse_lsb(CW[i]);
	CW[i] = dpf_xor(CW[i], sL);
	CW[i] = dpf_xor(CW[i], sR);

   }
}

void compute_next_word_leaf(){
	printf("\n compute next word leaf \n");
}

void GEN_(AES_KEY *key, int alpha, int n, unsigned char** k0, unsigned char **k1){
	
	int maxlayer = n;
	int maxlayer_minus7 = n - 7;

	/*
		Represent each node as:
		-> sL||tL||sR||tR
		-> s[...][0] corresponds to sL
		-> s[...][1] corresponds to sR
		-> t[...][0] corresponds to tL
		-> t[...][1] corresponds to tR			

	*/

	block  s[maxlayer + 1][2];
	int    t[maxlayer + 1][2];
	block  sCW[maxlayer];      //These are the correction words
	int    tCW[maxlayer][2];   //These are the correction word bits, they indicate to the server if the correction word should be applied
	
	
	s[0][0] = dpf_random_block(); // The root of the DPF tree is random
        s[0][1] = dpf_random_block();
        
	t[0][0] = dpf_lsb(s[0][0]); // One of the server gets 1, other 0 as the initial bit
        t[0][1] = t[0][0] ^ 1;
        
	s[0][0] = dpf_set_lsb_zero(s[0][0]);  // Why is this done?
        s[0][1] = dpf_set_lsb_zero(s[0][1]);

        int i;
        block s0[2], s1[2]; // 0=L,1=R
        #define LEFT 0
        #define RIGHT 1
        int t0[2], t1[2];

	block smax0, smax1;
	block finalblock;
	
	printf("%d =", maxlayer_minus7);
	for(i = 1; i <= maxlayer_minus7; i++){
		printf ("fff\n");
		block *S   = &sCW[i - 1];
		int *t0 = &tCW[i-1][LEFT];
		int *t1 = &tCW[i-1][RIGHT];
		
		//int   *t0  = &t[i-1][LEFT];
		//int   *t1  = &t[i-1][RIGHT];	 	
		
		//block *new_sL, *new_sR;
		//int *newt0, *newt1;

		block *new_sL = &s[i][0];
		block *new_sR = &s[i][1];
				
		int *newt0  = &t[i][LEFT];
		int *newt1  = &t[i][RIGHT];
		//compute_next_level(key,alpha,  n, k0, k1, block sL, block sR, int tL, int tR, block* sCW, int* tCWL, int* tCWR)
		compute_next_level(i, key, alpha, n - 7, k0, k1, s[i-1][0], s[i-1][1], t[i-1][0], t[i-1][1], new_sL, new_sR, newt0, newt1,  S, t0, t1);

	}
		smax0 = s[maxlayer_minus7][0];
		smax1 = s[maxlayer_minus7][1];
		
	int k = 2; 

	 
	 block CW[k]; // These are the new set of $k$ correction words
	 
	 compute_next_bit_leaf(key, alpha, smax0, smax1, k, CW);
	 
	 finalblock = CW[0];
	
	// The following bit of code needs to be modified
	unsigned char *buff0;
	unsigned char *buff1;
	buff0 = (unsigned char*) malloc(1 + 16 + 1 + 18 * maxlayer_minus7 + 16 * 2);
	buff1 = (unsigned char*) malloc(1 + 16 + 1 + 18 * maxlayer_minus7 + 16 * 2);

	if(buff0 == NULL || buff1 == NULL){
		printf("Memory allocation failed\n");
		exit(1);
	}

	buff0[0] = n;
	memcpy(&buff0[1], &s[0][0], 16);
	buff0[17] = t[0][0];
	for(i = 1; i <= maxlayer_minus7; i++){
		memcpy(&buff0[18 * i], &sCW[i-1], 16);
		buff0[18 * i + 16] = tCW[i-1][0];
		buff0[18 * i + 17] = tCW[i-1][1]; 
	}
	memcpy(&buff0[18 * maxlayer_minus7 + 18], &CW[0], 16); 
	memcpy(&buff0[18 * maxlayer_minus7 + 18 + 16], &CW[1], 16); 
	
	buff1[0] = n;
	memcpy(&buff1[18], &buff0[18], 18 * (maxlayer_minus7));
	memcpy(&buff1[1], &s[0][1], 16);
	buff1[17] = t[0][1];
	memcpy(&buff1[18 * maxlayer_minus7 + 18], &CW[0], 16);
	memcpy(&buff1[18 * maxlayer_minus7 + 18 + 16], &CW[1], 16); 
	
	*k0 = buff0;
	*k1 = buff1;
	
	
	for(i = maxlayer_minus7 + 1; i <= n; i++){
	  	
		block *S   = &sCW[i - 1];
		int   *t0  = &t[i-1][LEFT];
		int   *t1  = &t[i-1][RIGHT];	 	
		//block *new_sL, *new_sR;
		//int *newt0, *newt1;

		block *new_sL = &s[i][0];
		block *new_sR = &s[i][1];
				
		int *newt0  = &t[i][LEFT];
		int *newt1  = &t[i][RIGHT];
	  compute_next_level(i,key, alpha, n, k0, k1, s[i-1][0], s[i-1][1], t[i-1][0], t[i-1][1], new_sL, new_sR, newt0, newt1,  S, t0, t1);
	}
	
	for(i = 1; i <= 2; i++){
	 compute_next_word_leaf(); 
	}

}





void GEN(AES_KEY *key, int alpha, int n, unsigned char** k0, unsigned char **k1){
	int maxlayer = n - 7;
	//int maxlayer = n;

	block s[maxlayer + 1][2];
	int t[maxlayer + 1 ][2];
	block sCW[maxlayer];
	int tCW[maxlayer][2];

	s[0][0] =  dpf_random_block();
	dpf_cbnotnewline(s[0][0]);
	printf("\n");
	s[0][1] = dpf_random_block();
	dpf_cbnotnewline(s[0][0]);
	t[0][0] = dpf_lsb(s[0][0]);
	t[0][1] = t[0][0] ^ 1;
	s[0][0] = dpf_set_lsb_zero(s[0][0]);
	s[0][1] = dpf_set_lsb_zero(s[0][1]);

	int i;
	block s0[2], s1[2]; // 0=L,1=R
	#define LEFT 0
	#define RIGHT 1
	int t0[2], t1[2];
	
	for(i = 1; i<= maxlayer; i++){
		PRG(key, s[i-1][0], &s0[LEFT], &s0[RIGHT], &t0[LEFT], &t0[RIGHT], 0, 2);
		PRG(key, s[i-1][1], &s1[LEFT], &s1[RIGHT], &t1[LEFT], &t1[RIGHT], 0, 2);
	
		int keep, lose;
		int alphabit = getbit(alpha, n, i);
		printf("alphabit = %d", alphabit);
		if(alphabit == 0){
			keep = LEFT;
			lose = RIGHT;
		}else{
			keep = RIGHT;
			lose = LEFT;
		}

		sCW[i-1] = dpf_xor(s0[lose], s1[lose]);

		tCW[i-1][LEFT] = t0[LEFT] ^ t1[LEFT] ^ alphabit ^ 1;
		tCW[i-1][RIGHT] = t0[RIGHT] ^ t1[RIGHT] ^ alphabit;

		if(t[i-1][0] == 1){
			s[i][0] = dpf_xor(s0[keep], sCW[i-1]);
			t[i][0] = t0[keep] ^ tCW[i-1][keep];
		}else{
			s[i][0] = s0[keep];
			t[i][0] = t0[keep];
		}

		if(t[i-1][1] == 1){
			s[i][1] = dpf_xor(s1[keep], sCW[i-1]);
			t[i][1] = t1[keep] ^ tCW[i-1][keep];
		}else{
			s[i][1] = s1[keep];
			t[i][1] = t1[keep];
		}
		
	}

	block finalblock;
	finalblock = dpf_zero_block();
	finalblock = dpf_reverse_lsb(finalblock);

	char shift = (alpha) & 127;
	if(shift & 64){
		finalblock = dpf_left_shirt(finalblock, 64);
	}
	if(shift & 32){
		finalblock = dpf_left_shirt(finalblock, 32);
	}
	if(shift & 16){
		finalblock = dpf_left_shirt(finalblock, 16);
	}
	if(shift & 8){
		finalblock = dpf_left_shirt(finalblock, 8);
	}
	if(shift & 4){
		finalblock = dpf_left_shirt(finalblock, 4);
	}
	if(shift & 2){
		finalblock = dpf_left_shirt(finalblock, 2);
	}
	if(shift & 1){
		finalblock = dpf_left_shirt(finalblock, 1);
	}

	finalblock = dpf_reverse_lsb(finalblock);

	finalblock = dpf_xor(finalblock, s[maxlayer][0]);
	finalblock = dpf_xor(finalblock, s[maxlayer][1]);

	unsigned char *buff0;
	unsigned char *buff1;
	buff0 = (unsigned char*) malloc(1 + 16 + 1 + 18 * maxlayer + 16);
	buff1 = (unsigned char*) malloc(1 + 16 + 1 + 18 * maxlayer + 16);

	if(buff0 == NULL || buff1 == NULL){
		printf("Memory allocation failed\n");
		exit(1);
	}

	buff0[0] = n;
	memcpy(&buff0[1], &s[0][0], 16);
	buff0[17] = t[0][0];
	for(i = 1; i <= maxlayer; i++){
		memcpy(&buff0[18 * i], &sCW[i-1], 16);
		buff0[18 * i + 16] = tCW[i-1][0];
		buff0[18 * i + 17] = tCW[i-1][1]; 
	}
	memcpy(&buff0[18 * maxlayer + 18], &finalblock, 16); 

	buff1[0] = n;
	memcpy(&buff1[18], &buff0[18], 18 * (maxlayer));
	memcpy(&buff1[1], &s[0][1], 16);
	buff1[17] = t[0][1];
	memcpy(&buff1[18 * maxlayer + 18], &finalblock, 16);

	*k0 = buff0;
	*k1 = buff1;
} 

block EVAL(AES_KEY *key, unsigned char* k, int x){
	int n = k[0];
	int maxlayer = n - 7;
	//int maxlayer = n;
	
	block s[maxlayer + 1];
	int t[maxlayer + 1];
	block sCW[maxlayer];
	int tCW[maxlayer][2];
	block finalblock;

	memcpy(&s[0], &k[1], 16);
	t[0] = k[17];

	int i;
	for(i = 1; i <= maxlayer; i++){
		memcpy(&sCW[i-1], &k[18 * i], 16);
		tCW[i-1][0] = k[18 * i + 16];
		tCW[i-1][1] = k[18 * i + 17];
	}

	memcpy(&finalblock, &k[18 * (maxlayer + 1)], 16);

	block sL, sR;
	int tL, tR;
	for(i = 1; i <= maxlayer; i++){
		PRG(key, s[i - 1], &sL, &sR, &tL, &tR, 0, 2); 

		if(t[i-1] == 1){
			sL = dpf_xor(sL, sCW[i-1]);
			sR = dpf_xor(sR, sCW[i-1]);
			tL = tL ^ tCW[i-1][0];
			tR = tR ^ tCW[i-1][1];	
		}

		int xbit = getbit(x, n, i);
		if(xbit == 0){
			s[i] = sL;
			t[i] = tL;
		}else{
			s[i] = sR;
			t[i] = tR;
		}
	}

	block res;
	res = s[maxlayer];
	if(t[maxlayer] == 1){
		res = dpf_reverse_lsb(res);
	}

	if(t[maxlayer] == 1){
		res = dpf_xor(res, finalblock);
	}

	return res;
}


block* EVALFULL_(AES_KEY *key, unsigned char* k){
	int n = k[0];
	int maxlayer = n - 7;
	//int maxlayer = n;
	int maxlayeritem = 1 << (maxlayer);

	block s[2][maxlayeritem];
	int t[2][maxlayeritem];

	int curlayer = 1;

	block sCW[maxlayer];
	int tCW[maxlayer][2];
	
	int kk = 2;
	
	block CW[kk];

	memcpy(&s[0][0], &k[1], 16);
	t[0][0] = k[17];

	int i, j;
	for(i = 1; i <= maxlayer; i++){
		memcpy(&sCW[i-1], &k[18 * i], 16);
		tCW[i-1][0] = k[18 * i + 16];
		tCW[i-1][1] = k[18 * i + 17];
	}

	memcpy(&CW[0], &k[18 * (maxlayer + 1)], 16);
	memcpy(&CW[1], &k[18 * (maxlayer + 1) + 16], 16);

	block sL, sR;
	int tL, tR;
	for(i = 1; i <= maxlayer; i++){
		int itemnumber = 1 << (i - 1);
		for(j = 0; j < itemnumber; j++){
			PRG(key, s[1 - curlayer][j], &sL, &sR, &tL, &tR, 0, 2); 

			if(t[1 - curlayer][j] == 1){
				sL = dpf_xor(sL, sCW[i-1]);
				sR = dpf_xor(sR, sCW[i-1]);
				tL = tL ^ tCW[i-1][0];
				tR = tR ^ tCW[i-1][1];	
			}

			s[curlayer][2 * j] = sL;
			t[curlayer][2 * j] = tL;
			s[curlayer][2 * j + 1] = sR; 
			t[curlayer][2 * j + 1] = tR;
		}
		curlayer = 1 - curlayer;
	}

	int itemnumber = 1 << maxlayer;
	block *res = (block*) malloc(sizeof(block) * itemnumber);

	for(j = 0; j < itemnumber; j ++){
		printf("1 - curlayer = %d \n", (1-curlayer));  
		res[j] = s[1 - curlayer][j];

		if(t[1 - curlayer][j] == 0){
			res[j] = dpf_reverse_lsb(res[j]);
		}

		if(t[1 - curlayer][j] == 0){
			res[j] = dpf_xor(res[j], CW[1]);
		}
		
		if(t[1 - curlayer][j] == 1){
			//res[j] = dpf_reverse_lsb(res[j]);
		}

		if(t[1 - curlayer][j] == 1){
			res[j] = dpf_xor(res[j], CW[0]);
		}
	}

	return res;
}


block* EVALFULL(AES_KEY *key, unsigned char* k){
	int n = k[0];
	int maxlayer = n - 7;
	//int maxlayer = n;
	int maxlayeritem = 1 << (maxlayer);

	block s[2][maxlayeritem];
	int t[2][maxlayeritem];

	int curlayer = 1;

	block sCW[maxlayer];
	int tCW[maxlayer][2];
	block finalblock;

	memcpy(&s[0][0], &k[1], 16);
	t[0][0] = k[17];

	int i, j;
	for(i = 1; i <= maxlayer; i++){
		memcpy(&sCW[i-1], &k[18 * i], 16);
		tCW[i-1][0] = k[18 * i + 16];
		tCW[i-1][1] = k[18 * i + 17];
	}

	memcpy(&finalblock, &k[18 * (maxlayer + 1)], 16);

	block sL, sR;
	int tL, tR;
	for(i = 1; i <= maxlayer; i++){
		int itemnumber = 1 << (i - 1);
		for(j = 0; j < itemnumber; j++){
			PRG(key, s[1 - curlayer][j], &sL, &sR, &tL, &tR, 0, 2); 

			if(t[1 - curlayer][j] == 1){
				sL = dpf_xor(sL, sCW[i-1]);
				sR = dpf_xor(sR, sCW[i-1]);
				tL = tL ^ tCW[i-1][0];
				tR = tR ^ tCW[i-1][1];	
			}

			s[curlayer][2 * j] = sL;
			t[curlayer][2 * j] = tL;
			s[curlayer][2 * j + 1] = sR; 
			t[curlayer][2 * j + 1] = tR;
		}
		curlayer = 1 - curlayer;
	}

	int itemnumber = 1 << maxlayer;
	block *res = (block*) malloc(sizeof(block) * itemnumber);

	for(j = 0; j < itemnumber; j ++){
		res[j] = s[1 - curlayer][j];

		if(t[1 - curlayer][j] == 1){
			res[j] = dpf_reverse_lsb(res[j]);
		}

		if(t[1 - curlayer][j] == 1){
			res[j] = dpf_xor(res[j], finalblock);
		}
	}

	return res;
}


static int getbit(int x, int n, int b){
	return ((unsigned int)(x) >> (n - b)) & 1;
}
/*
int main(){
	long long userkey1 = 597349; long long userkey2 = 121379; 
	block userkey = dpf_make_block(userkey1, userkey2);

	dpf_seed(NULL);

	AES_KEY key;
	AES_set_encrypt_key(userkey, &key);

	unsigned char *k0;
	unsigned char *k1;

	GEN(&key, 26943, 16, &k0, &k1);
	
	block res1;
	block res2;

	res1 = EVAL(&key, k0, 0);
	res2 = EVAL(&key, k1, 0);
	dpf_cb(res1);
	dpf_cb(res2);
	dpf_cb(dpf_xor(res1, res2));

	res1 = EVAL(&key, k0, 128);
	res2 = EVAL(&key, k1, 128);
	dpf_cb(res1);
	dpf_cb(res2);
	dpf_cb(dpf_xor(res1, res2));

	block *resf0, *resf1;
	resf0 = EVALFULL(&key, k0);
	resf1 = EVALFULL(&key, k1);

	int j;
	for(j = 0; j < 512; j++){
		printf("Group %d\n", j);

		dpf_cb(resf0[j]);
		dpf_cb(resf1[j]);
		dpf_cb(dpf_xor(resf0[j], resf1[j]));
	}

	return 0;
}
*/
