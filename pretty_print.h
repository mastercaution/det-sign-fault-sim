#pragma once
#include <stdint.h>
#include <gmp.h>

// Pretty print defines
#define PP_COL_DEFAULT "\e[39m"
#define PP_COL_BLUE "\e[36m"
#define PP_COL_GREEN "\e[32m"
#define PP_COL_RED "\e[31m"
#define pretty_print_cfg(location) 	char *pp_cfg_backup = pp_location; \
									pp_location = location;
#define pretty_print_cfg_rm() pp_location = pp_cfg_backup;
#define pretty_print(prefix, data, size) 		pretty_print_col(prefix, data, size, NULL)
#define pretty_print_v(prefix, data, size) 		pretty_print_v_col(prefix, data, size, NULL)
#define pretty_print_mpz(prefix, data)			pretty_print_mpz_col(prefix, data, NULL)
#define pretty_print_v_mpz(prefix, data) 		pretty_print_v_mpz_col(prefix, data, NULL)
#define pretty_print_text(text) 				pretty_print_col(text, NULL, 0, NULL)
#define pretty_print_v_text(text) 				pretty_print_v_col(text, NULL, 0, NULL)
#define pretty_print_text_col(text, color) 		pretty_print_col(text, NULL, 0, color)
#define pretty_print_v_text_col(text, color) 	pretty_print_v_col(text, NULL, 0, color)


extern int pp_verbose;
extern int pp_color;
extern char *pp_location;

void pretty_print_col(const char *prefix, const uint8_t *data, const int size, const char *color);
void pretty_print_v_col(const char *prefix, const uint8_t *data, const int size, const char *color);
void pretty_print_mpz_col(const char *prefix, const mpz_t data, const char *color);
void pretty_print_v_mpz_col(const char *prefix, const mpz_t data, const char *color);