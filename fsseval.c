#include <stdio.h>
#include <string.h>
#include "utils.h"

int getsize(int n){
	int maxlayer = n - 7;

	return (18 * (maxlayer + 1) + 16);
}

int main(int argc, char** argv){
	  
      
	long long userkey1 = 597349; long long userkey2 = 121379; 
	block userkey = dpf_make_block(userkey1, userkey2);

	dpf_seed(NULL);

	AES_KEY key;
	AES_set_encrypt_key(userkey, &key);
	if(argc != 3){
		printf("format: fsseval N filename\n");
		exit(0);
	}

	int n;
	char filename[1001];
	sscanf(argv[1], "%d", &n);
	sscanf(argv[2], "%s", filename);
      
	
	unsigned char *k = (unsigned char*) malloc(getsize(n));

	
	if(k == NULL){
		printf("Failed to allocate a memory space.\n");
		exit(0);
	}
	
	FILE *fp = fopen(filename, "rb");
	if(fp == NULL){
		printf("Failed to open the file.\n");
		exit(0);
	}

	fread(k, getsize(n), 1, fp);
	fclose(fp);
	block *resf;
	resf = EVALFULL_(&key, k); // k is the DPF key..
	int j;
	int totalblocknumber = (1 << n) / 128;
	for(j = 0; j < totalblocknumber; j++){
		dpf_cbnotnewline(resf[j]);
		printf("\n");
	}

	return 0;
}
