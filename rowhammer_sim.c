#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "rowhammer_sim.h"
#include "pretty_print.h"

static int call_nr = 0;

void rowhammer_sim_attack(const uint8_t *parameter, size_t param_len)
{
	pretty_print_cfg("[RHSIM] {rowhammer_sim.c:rowhammer_sim_attack()}");

	// Do nothing if it is the first call
	if (call_nr >= 2) {
		pretty_print_v_text("Attack called (fault injection run)");
		rowhammer_sim(parameter, param_len);
	} else {
		pretty_print_v_text("Attack called (normal run)");
	}

	pretty_print_cfg_rm();
	return;
}

void rowhammer_sim(const uint8_t *parameter, size_t param_len)
{
	pretty_print_cfg("[RHSIM] {rowhammer_sim.c:rowhammer_sim()}");
	pretty_print_v_text("Rowhammer simulation called");

	// Change parameter for the second call
	// Print original parameter
	pretty_print_v("Parameter:", parameter, param_len);

	// Add 1 to first byte
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
	// HACK: const is no more
	uint8_t *mut_param = parameter;
#pragma GCC diagnostic pop
	mut_param[0] = mut_param[0] + 1;
	pretty_print_v_text("Parameter modified");

	// Print modified parameter
	pretty_print_v("Parameter:", parameter, param_len);

	pretty_print_cfg_rm();
	return;
}

void rowhammer_sim_inc()
{
	call_nr++;
}