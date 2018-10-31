#include <stdio.h>
#include <string.h>
#include "b64.h"
#include "utils.h"

int getsize(unsigned char *k){
	char n = k[0];
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
		printf("format: fssgen N alpha\n");
		exit(0);
	}

	int n, alpha;
	sscanf(argv[1], "%d", &n);
	sscanf(argv[2], "%d", &alpha);

	unsigned char *k0;
	unsigned char *k1;

	GEN_(&key, alpha, n, &k0, &k1);
	//GEN(&key, alpha, n, &k0, &k1);
	
	int ksize = getsize(k0);

	FILE* testfp = fopen("./k0", "wb");
	fwrite(k0, ksize, 1, testfp);
	fclose(testfp);

	testfp = fopen("./k1", "wb");
	fwrite(k1, ksize, 1, testfp);
	fclose(testfp);

	return 0;
}
