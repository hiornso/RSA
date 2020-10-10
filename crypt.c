#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h> // only needed if not using /dev/urandom, but include just in case.
#include <stdint.h>
#include <pthread.h>
#include <gmp.h>

// defaults for RSA key generation
#define NBITS 4096 // for 4096-bit key
#define MIN_EXP 65537
#define ITERATIONS 64

#define USE_DEV_URANDOM 0	// much better, uses proper entropy/cryptographically secure randomness,
							// but I couldn't get it to work (I think this is an issue with MinGW+MSYS2,
							// and enabling it should work on proper *nix systems, but I haven't verified
							// this).
#define PRINT_PRIME_TIME 1
#define PRINT_PRIMES 0
#define PRINT_KEYS 0

#define THREADS 8 // on how many threads to search for primes

#define PUB_KEY_DEFAULT_FILE "pub_rsa_key.txt"
#define PRIVATE_KEY_DEFAULT_FILE "private_rsa_key.txt"

#define KEEP_OLD_KEYGEN 1
#define DEFAULT_KEYGEN_VERSION 1

// defaults for encryption/decryption
#define PADDING 16 // no. of padding bytes

#define OUTFILE_ENCRYPT_DEFAULT "encrypted.txt"
#define OUTFILE_DECRYPT_DEFAULT "decrypted.txt"

enum actions {
	NONE,
	KEYGEN,
	ENCRYPT,
	DECRYPT
};

typedef struct {
	unsigned int nBits;
	unsigned int iterations;
	unsigned int found;
	unsigned int nPrimes;
	mpz_t *primes;
} PrimeArg;

typedef struct {
	unsigned long seed;
	PrimeArg* primeArg;
} PrimeGenArg;

void *generateRandomPrime(void *arg)
{
	PrimeArg *args = ((PrimeGenArg*)arg)->primeArg;
	mpz_t n;
	mpz_init2(n,args->nBits);
	
	gmp_randstate_t rng;
	gmp_randinit_mt(rng);
	gmp_randseed_ui(rng,((PrimeGenArg*)arg)->seed);
	
	while(args->found < args->nPrimes){ // need more primes
		do {
			mpz_urandomb(n,rng,args->nBits); // generate a random number (nBits bits long) using our private rng
			mpz_setbit(n,0); // no even primes (not interested in 2)
		} while( mpz_probab_prime_p(n,args->iterations) == 0 && args->found < args->nPrimes ); 
		// not using mpz_next_prime because this way we can control the number of iterations of checks 
		// (mpz_next_prime only uses 25 which is insufficient for cryptographic purposes)
		
		++args->found; // as fast as you can, reserve a space (if we exited because args->found was already 2, doesn't matter, we'll still see)
		if(args->found < args->nPrimes + 1){ // if there is a free space available
			mpz_set(args->primes[args->found - 1],n); // copy the prime we found into the array
		}
	}
	
	mpz_clear(n);
	gmp_randclear(rng);
}

#if KEEP_OLD_KEYGEN
void generateRandomPrime_old(mpz_t n, int nBits, gmp_randstate_t rng, int iterations)
{
	do {
		mpz_urandomb(n,rng,nBits);
		mpz_setbit(n,0);
	} while( mpz_probab_prime_p(n,iterations) == 0 ); 
	// not using mpz_next_prime because this way we can control the number of iterations of checks 
	// (mpz_next_prime only uses 25 which is insufficient for cryptographic purposes)
}

void init_prime(
	mpz_t p, 
	char *p_str,
	unsigned int nbits,
	unsigned int prime_iterations,
	gmp_randstate_t rng,
	char print_prime_gen_time,
	char print_generated_primes,
	char c
	)
{
	if(p_str == NULL){
		mpz_init2(p,nbits);
		struct timeval start_time,current_time;
		if(print_prime_gen_time)
			gettimeofday(&start_time, NULL);
		generateRandomPrime_old(p, nbits, rng, prime_iterations);
		if(print_prime_gen_time){
			gettimeofday(&current_time, NULL);
			printf("Generated prime %c",c);
			if(print_generated_primes)
				gmp_printf("=%Zi",p);
			printf(" in %f seconds\n",((unsigned long long)current_time.tv_sec*1e+6+current_time.tv_usec - (start_time.tv_sec*1e+6+start_time.tv_usec))/1000000.f);
		}else if(print_generated_primes){
			gmp_printf("%c=%Zi\n",c,p);
		}
		fflush(stdout);
	}else{
		mpz_init_set_str (p, p_str, 10);
	}
}
#endif

void rsa_keygen(
	unsigned int nbits,
	unsigned int min_exp,
	unsigned int prime_iterations,
	char *p_str,
	char *q_str,
	char print_prime_gen_time,
	char print_generated_primes,
	char print_keys,
	char *pub_key_file,
	char *private_key_file,
	gmp_randstate_t rng,
	unsigned int threads
#if KEEP_OLD_KEYGEN
	,char keygen_version
#endif
	)
{	
	mpz_t p,q;

#if KEEP_OLD_KEYGEN
	if(keygen_version == 1){
#endif
		char *strs[2] = {p_str,q_str};
		mpz_t primes[2];
		unsigned int start = 0, nPrimes = 2;
		for(int i = 0; i < 2; ++i){
			if(strs[i] != NULL){
				mpz_init_set_str (primes[i], strs[i], 10);
				start += 1 - i;
				--nPrimes;
			}else{
				mpz_init2(primes[i],nbits);
			}
		}
		PrimeArg arg = (PrimeArg){
			nbits,
			prime_iterations,
			0,
			nPrimes,
			primes + start
		};
		PrimeGenArg args[threads];
		pthread_t tid[threads];
		mpz_t s;
		unsigned long seed;
		struct timeval start_time, current_time;
		mpz_init2(s,sizeof(seed) << 3);
		for(int i = 0; i < threads; ++i){
			mpz_urandomb(s,rng,sizeof(seed) << 3);
			mpz_export(&seed,NULL,1,sizeof(seed),0,0,s);
			args[i] = (PrimeGenArg){seed + 1,&arg};
			pthread_create(tid+i,NULL,generateRandomPrime,args+i);
		}
		if(print_prime_gen_time)
			gettimeofday(&start_time,NULL);
		
		mpz_clear(s);
		
		for(int i = 0; i < threads; ++i)
			pthread_join(tid[i],NULL);
		
		if(print_prime_gen_time){
			gettimeofday(&current_time,NULL);
			printf("Generated 2 primes in %f seconds\n",((unsigned long long)current_time.tv_sec*1e+6+current_time.tv_usec - (start_time.tv_sec*1e+6+start_time.tv_usec))/1000000.f);
		}
		
		p[0] = primes[0][0];
		q[0] = primes[1][0];
		
		if(print_generated_primes)
			gmp_printf("p:%Zi\nq:%Zi\n",p,q);
#if KEEP_OLD_KEYGEN
	}else{
		init_prime(p,p_str,nbits,prime_iterations,rng,print_prime_gen_time,print_generated_primes,'p');
		init_prime(q,q_str,nbits,prime_iterations,rng,print_prime_gen_time,print_generated_primes,'q');
	}
#endif
	
	mpz_t n,v;
	
	mpz_init2(n,2 * nbits);
	mpz_init2(v,2 * nbits);
	
	mpz_mul(n,p,q); // n = p * q
	
	mpz_sub_ui(p,p,1);
	mpz_sub_ui(q,q,1);
	mpz_mul(v,p,q); // v = (p - 1) * (q - 1)
	
	mpz_t e,gcd,d;
	
	mpz_init_set_ui(e,min_exp - 2); // k = min_exp (normally 65537), -2 since we add 2 in the loop
	mpz_init(gcd);
	mpz_init(d);
	
	do {
		mpz_add_ui(e,e,2);
		mpz_gcdext(gcd,d,NULL,e,v); // find d such that de + kv = 1 where k is some constant
	} while( mpz_cmp_si(gcd,1) != 0 ); // while gcd != 1
	
	// now make d positive
	
	if( mpz_sgn(d) == -1 ){ // if d < 0
		mpz_fdiv_r(d,d,v);
	}
	
	if(print_keys){
		gmp_printf("Your public key is:\n(%Zi,%Zi)\nYour private key is:\n(%Zi,%Zi)\n",e,n,d,n);
		fflush(stdout);
	}

	FILE *outfile;
	if(pub_key_file != NULL){
		outfile = fopen(pub_key_file, "w");
		if(outfile == NULL)
			printf("Failed to open %s to write public key.",pub_key_file);
		else{
			gmp_fprintf(outfile,"%Zi\n%Zi",e,n);
			fclose(outfile);
		}
	}
	if(private_key_file != NULL){
		outfile = fopen(private_key_file, "w");
		if(outfile == NULL)
			printf("Failed to open %s to write private key.",private_key_file);
		else{
			gmp_fprintf(outfile,"%Zi\n%Zi",d,n);
			fclose(outfile);
		}
	}
	
	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(n);
	mpz_clear(v);
	mpz_clear(e);
	mpz_clear(d);
	mpz_clear(gcd);
	
	
}

void crypt(
	char mode,
	char *infile,
	char *outfile,
	char *key_file,
	unsigned int padding,
	gmp_randstate_t rng
	)
{
	mpz_t e,n,n2;
	mpz_init(e);
	mpz_init(n);
	mpz_init(n2);
	
	FILE *key_f = fopen(key_file,"r");
	if(key_f == NULL){
		printf("Failed to read %s key from %s",(mode ==  ENCRYPT ? "public" : "private"),key_file);
		return;
	}
	gmp_fscanf(key_f,"%Zi\n%Zi",e,n);
	fclose(key_f);
	
	mpz_set(n2,n); // n2 = n
	unsigned int b = 0;
	do {
		b = mpz_scan1(n2,b);
		mpz_clrbit(n2,b);
	} while( mpz_sgn(n2) != 0 ); // while n2 != 0
	mpz_clear(n2);
	
	b >>= 3; // b/=8
	b -= padding; // now b is the number of bytes of data we can get per chunk.
	
	if(mode == ENCRYPT && b < 0){
		printf("RSA key too small to be useful (can't even fit padding bytes). Please use a more suitably sized key.");
		return;
	}
	
	FILE *in_f = fopen(infile,"rb");
	if(in_f == NULL){
		printf("Error opening file to be %s %s for reading.",(mode == ENCRYPT ? "encrypted" : "decrypted"),infile);
		return;
	}
	
	FILE *out_f = fopen(outfile,"wb");
	if(out_f == NULL){
		printf("Error opening file %s in order to write %s.",outfile,(mode == ENCRYPT ? "ciphertext" : "decrypted data"));
		return;
	}
	
	uint64_t bytesRead, offset = 0; // to avoid issues with diff. sized ints on diff. systems we use a fixed size int. Please don't try to encrypt a 2^64 byte message.
	char *chunk = malloc(sizeof(char) * (b + padding) + 1) + 1;
	if(chunk == NULL){
		printf("Error: failed to allocate memory to store the message chunk in.");
		return;
	}
	mpz_t ch,randoms;
	mpz_init(ch);
	mpz_init(randoms);
	
	if(mode == ENCRYPT){
		do {
			bytesRead = fread(chunk, sizeof(char), b, in_f);
			mpz_urandomb(randoms,rng,(b - bytesRead + padding) << 3);
			mpz_export(chunk + bytesRead, NULL, 1, sizeof(chunk[0]),0,0,randoms);
			mpz_import(ch,b + padding,1,sizeof(chunk[0]),0,0,chunk); // encode message as an integer, with random padding bytes
			mpz_powm_sec(ch,ch,e,n);
			offset += mpz_out_raw(out_f,ch);
		} while( bytesRead == b ); // technically this does mean that if the size of the message is an exact multiple of the chunk size, we write a chunk of just random data.
								   // this might be improved later, but really the goal here is security, not efficiency.
		mpz_urandomb(randoms,rng,(b - sizeof(bytesRead) + padding) << 3);
		mpz_export(chunk + sizeof(bytesRead), NULL, 1, sizeof(chunk[0]),0,0,randoms);
		*((uint64_t*)chunk) = bytesRead;
		mpz_import(ch,b + padding,1,sizeof(chunk[0]),0,0,chunk); // encrypt the number of message bytes in the last chunk
		mpz_powm_sec(ch,ch,e,n);
		mpz_out_raw(out_f,ch);
		fwrite(&offset, sizeof(offset),1,out_f); // we don't have to encrypt this because it's not actual data, just an optimisation - it just says how many
												 // bytes along the last chunk is. One could find this number just by counting in the file.
	}else{ // mode == DECRYPT
		mpz_t pre;
		mpz_init(pre); // used to ensure the chunks are aligned correctly when exported as a char[]
		mpz_setbit(pre,(b + padding) << 3);
		fseek(in_f, -8, SEEK_END);
		fread(&offset, sizeof(offset), 1, in_f);
		fseek(in_f, offset, SEEK_SET);
		mpz_inp_raw(ch, in_f);
		mpz_powm_sec(ch,ch,e,n);
		mpz_add(ch,ch,pre);
		mpz_export(chunk-1,NULL,1,sizeof(chunk[0]),0,0,ch);
		uint64_t bytesWritten = *((uint64_t*)chunk), cumulative = 0;
		fseek(in_f, 0, SEEK_SET);
		while(1){
			bytesRead = mpz_inp_raw(ch, in_f);
			cumulative += bytesRead;
			mpz_powm_sec(ch,ch,e,n);
			mpz_add(ch,ch,pre);
			mpz_export(chunk-1,NULL,1,sizeof(chunk[0]),0,0,ch);
			if(cumulative == offset){
				fwrite(chunk,sizeof(chunk[0]),bytesWritten,out_f);
				break;
			}else{
				fwrite(chunk,sizeof(chunk[0]),b,out_f);
			}
		}
		mpz_clear(pre);
	}
	
	mpz_clear(ch);
	mpz_clear(randoms);
	mpz_clear(e);
	mpz_clear(n);
	
	fclose(in_f);
	fclose(out_f);
	
	free(chunk);
}

int main(int argc, char *argv[])
{
	
/*
--keygen [--pub-key-file "path/to/file/for/public/key"] [--private-key-file "path/to/file/for/private/key"] [--nbits 4096] [--min_exp 65537] [--print-prime-gen-time 0] [--use-dev-urandom 1] [--print-primes 0] [--print-keys 0]
--encrypt "path/to/input/file" [--outfile "path/to/output/file"] [--pub-key-file "path/to/public/key"] [--padding 16]
--decrypt "path/to/input/file" [--outfile "path/to/output/file"] [--private-key-file "path/to/private/key"] [--padding 16]
*/
	char pub_key_default_file[] = PUB_KEY_DEFAULT_FILE;
	char private_key_default_file[] = PRIVATE_KEY_DEFAULT_FILE;
	char outfile_encrypt_default[] = OUTFILE_ENCRYPT_DEFAULT;
	char outfile_decrypt_default[] = OUTFILE_DECRYPT_DEFAULT;
	
	char action = NONE;
	char *pub_key_file = NULL;
	char *private_key_file = NULL;
	char *infile = NULL;
	char *outfile = NULL;
	unsigned int nbits = NBITS;
	unsigned int min_exp = MIN_EXP;
	unsigned int prime_iterations = ITERATIONS;
	char use_dev_urandom = USE_DEV_URANDOM;
	char print_prime_gen_time = PRINT_PRIME_TIME;
	char print_primes = PRINT_PRIMES;
	char print_keys = PRINT_KEYS;
	unsigned int threads = THREADS;
	unsigned int padding = PADDING;
	char *p = NULL;
	char *q = NULL;
#if KEEP_OLD_KEYGEN
	char keygen_version = DEFAULT_KEYGEN_VERSION;
#endif
	
	for(int i = 1; i < argc; ++i){
#if KEEP_OLD_KEYGEN
		if(strcmp(argv[i],"--keygen-version") == 0){
			keygen_version = atoi(argv[++i]);
		}else
#endif
		if(strcmp(argv[i],"--keygen") == 0){
			action = KEYGEN;
		}else if(strcmp(argv[i],"--encrypt") == 0){
			action = ENCRYPT;
		}else if(strcmp(argv[i],"--decrypt") == 0){
			action = DECRYPT;
		}else if(strcmp(argv[i],"--nbits") == 0){
			nbits = atoi(argv[++i]);
		}else if(strcmp(argv[i],"--min-exp") == 0){
			min_exp = atoi(argv[++i]);
		}else if(strcmp(argv[i],"--prime-iterations") == 0){
			prime_iterations = atoi(argv[++i]);
		}else if(strcmp(argv[i],"--use-dev-urandom") == 0){
			use_dev_urandom = 1;
		}else if(strcmp(argv[i],"--no-dev-urandom") == 0){
			use_dev_urandom = 0;
		}else if(strcmp(argv[i],"--print-prime-gen-time") == 0){
			print_prime_gen_time = 1;
		}else if(strcmp(argv[i],"--no-print-prime-gen-time") == 0){
			print_prime_gen_time = 0;
		}else if(strcmp(argv[i],"--print-primes") == 0){
			print_primes = 1;
		}else if(strcmp(argv[i],"--no-print-primes") == 0){
			print_primes = 0;
		}else if(strcmp(argv[i],"--print-keys") == 0){
			print_keys = 1;
		}else if(strcmp(argv[i],"--no-print-keys") == 0){
			print_keys = 0;
		}else if(strcmp(argv[i],"--padding") == 0){
			padding = atoi(argv[++i]);
		}else if(strcmp(argv[i],"--pub_key_file") == 0){
			pub_key_file = argv[++i];
		}else if(strcmp(argv[i],"--private_key_file") == 0){
			private_key_file = argv[++i];
		}else if(strcmp(argv[i],"--infile") == 0){
			infile = argv[++i];
		}else if(strcmp(argv[i],"--outfile") == 0){
			outfile = argv[++i];
		}else if(strcmp(argv[i],"--specify-p") == 0){
			p = argv[++i];
		}else if(strcmp(argv[i],"--specify-q") == 0){
			q = argv[++i];
		}else if(strcmp(argv[i],"--threads") == 0){
			threads = atoi(argv[++i]);
		}else{
			printf("Error: Unknown argument %s.",argv[i]);
			return -1;
		}
	}
	
	unsigned long long int r;
	struct timeval current_time;
	
	if(use_dev_urandom){
		FILE *randoms = fopen("/dev/urandom","rb");
		if(randoms == NULL){
			printf("Error opening /dev/urandom");
			return -1;
		}
		fread(&r,sizeof(r),1,randoms);
		fclose(randoms);
	}else{
		gettimeofday(&current_time, NULL);
		r = current_time.tv_sec * 1e+6 + current_time.tv_usec;
	}
	
	gmp_randstate_t rng;
	gmp_randinit_mt(rng);
	gmp_randseed_ui(rng,(unsigned long int)r);
	
	if(action == ENCRYPT){
		if(infile == NULL){
			printf("Error: no path specified for input file. Please use --infile.");
			return -1;
		}
		if(pub_key_file == NULL){
			printf("No input path for public key specified. Defaulting to \"%s\"\n",pub_key_default_file);
			pub_key_file = pub_key_default_file;
		}
		if(outfile == NULL){
			printf("No output path for encrypted data specified. Defaulting to \"%s\"\n",outfile_encrypt_default);
			outfile = outfile_encrypt_default;
		}
		fflush(stdout);
		crypt(ENCRYPT,infile,outfile,pub_key_file,padding,rng);
	}else if(action == DECRYPT){
		if(infile == NULL){
			printf("Error: no path specified for input file. Please use --infile.");
			return -1;
		}
		if(private_key_file == NULL){
			printf("No input path for private key specified. Defaulting to \"%s\"\n",private_key_default_file);
			private_key_file = private_key_default_file;
		}
		if(outfile == NULL){
			printf("No output path for decrypted data specified. Defaulting to \"%s\"\n",outfile_decrypt_default);
			outfile = outfile_decrypt_default;
		}
		fflush(stdout);
		crypt(DECRYPT,infile,outfile,private_key_file,padding,rng);
	}else if(action == KEYGEN){
		if(p == NULL && q == NULL)
			printf("Generating %i-bit RSA key...\n",nbits & -2);
		if(pub_key_file == NULL){
			printf("No output path for public key specified. Defaulting to \"%s\"\n",pub_key_default_file);
			pub_key_file = pub_key_default_file;
		}
		if(private_key_file == NULL){
			printf("No output path for private key specified. Defaulting to \"%s\"\n",private_key_default_file);
			private_key_file = private_key_default_file;
		}
		fflush(stdout);
		rsa_keygen(nbits >> 1,min_exp,prime_iterations,p,q,print_prime_gen_time,print_primes,print_keys,pub_key_file,private_key_file,rng,threads
#if KEEP_OLD_KEYGEN
		,keygen_version
#endif
		);
	}else{
		printf("No action was specified. Please use one of --keygen, --encrypt or --decrypt.");
		return -1;
	}
	
	return 0;
}
