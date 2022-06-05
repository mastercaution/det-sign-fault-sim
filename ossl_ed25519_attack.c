#include <stdio.h>
#include <stdint.h>

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
uint8_t sig[64];

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
	size_t sig_len = sizeof(sig);
	
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
	for (int i = 0; i < SIGN_RUNS; i++) {
		if (!EVP_DigestSignInit(mdctx, &pctx, NULL, NULL, pkey))
		goto err;

		// One-shot-sign (update and final are not supported with Ed25519)
		log("\e[36m[ATCK] {prototype.c:main()}: Start Ed25519 sign\e[39m\n");
		if (!EVP_DigestSign(mdctx, sig, &sig_len, kmsg, sizeof(kmsg)))
			goto err;
		log("\e[36m[ATCK] {prototype.c:main()}: End Ed25519 sign\e[39m\n");

		// Print signature
		puts("Raw signature: (base64)");
		BIO_write(b64, sig, sig_len);
		BIO_flush(b64);
		puts("");

		// Check signature
		// Doc: https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestVerifyInit.html
		if (!EVP_DigestVerifyInit(mdctx, &pctx, NULL, NULL, pkey))
			goto err;
		ret = EVP_DigestVerify(mdctx, sig, sig_len, kmsg_original, sizeof(kmsg_original));
		if (ret == 1)
			puts("\e[32mSignature successfully verified.\e[39m");
		else if (ret == 0)
			puts("\e[31mSignature could not be verified.\e[39m");
		else
			goto err;
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