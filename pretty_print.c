#include <stdio.h>
#include <stdint.h>
#include <gmp.h>

#include "pretty_print.h"

int pp_verbose = 0;
int pp_color = 1;
char *pp_location = "[ATCK]";

void pretty_print_col(const char *prefix, const uint8_t *data, const int size, const char *color)
{
	char *pp_col = "";
	char *pp_col_def = "";
	if (pp_color) {
		pp_col = (color == NULL) ? "" : (char *)color;
		pp_col_def = (color == NULL) ? "" : PP_COL_DEFAULT;
	}

	printf("%s%s ", pp_col, prefix);
	if (size) {
		printf("0x");
		for (int i = size - 1; i >= 0; i--)
			printf("%02x", data[i]);
		printf(" (%d)%s\n", size, pp_col_def);
	} else {
		printf("%s\n", pp_col_def);
	}
}

void pretty_print_v_col(const char *prefix, const uint8_t *data, const int size, const char *color)
{
	if (!pp_verbose)
		return;

	char *pp_col_blue = "";
	char *pp_col_def = "";
	if (pp_color) {
		pp_col_blue = (color == NULL) ? PP_COL_BLUE : (char *)color;
		pp_col_def = PP_COL_DEFAULT;
	}

	printf("%s%s %s ", pp_col_blue, pp_location, prefix);
	if (size) {
		printf("0x");
		for (int i = size - 1; i >= 0; i--)
			printf("%02x", data[i]);
		printf(" (%d)%s\n", size, pp_col_def);
	} else {
		printf("%s\n", pp_col_def);
	}
}

void pretty_print_mpz_col(const char *prefix, const mpz_t data, const char *color)
{
	char *pp_col_blue = "";
	char *pp_col_def = "";
	if (pp_color) {
		pp_col_blue = (color == NULL) ? "" : (char *)color;
		pp_col_def = PP_COL_DEFAULT;
	}

	gmp_printf("%s%s 0x%Zx (%d)%s\n", pp_col_blue, prefix, data, mpz_size(data) * sizeof(uintptr_t), pp_col_def);
}

void pretty_print_v_mpz_col(const char *prefix, const mpz_t data, const char *color)
{
	if (!pp_verbose)
		return;

	char *pp_col_blue = "";
	char *pp_col_def = "";
	if (pp_color) {
		pp_col_blue = (color == NULL) ? PP_COL_BLUE : (char *)color;
		pp_col_def = PP_COL_DEFAULT;
	}

	gmp_printf("%s%s %s 0x%Zx (%d)%s\n", pp_col_blue, pp_location, prefix, data, mpz_size(data) * sizeof(uintptr_t), pp_col_def);
}