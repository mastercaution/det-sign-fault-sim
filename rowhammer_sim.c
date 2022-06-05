#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "rowhammer_sim.h"

// stdout logger
#ifdef RHSIM_VERBOSE
	#define log(...) printf(__VA_ARGS__)
#else
	#define log(...)
#endif

static int call_nr = 0;

void rowhammer_sim_attack(const uint8_t *message, size_t message_len)
{
	log("\e[36m[RHSIM] {rowhammer_sim.c:rowhammer_sim_attack()}: Attack called\e[39m\n");
	call_nr++;

	// Do nothing if it is the first call
	if (call_nr >= 2) {
		rowhammer_sim(message, message_len);
	}
}

void rowhammer_sim(const uint8_t *message, size_t message_len)
{
	log("\e[36m[RHSIM] {rowhammer_sim.c:rowhammer_sim()}: Rowhammer simulation called\e[39m\n");

	// Change message for the second call
	// Print original message
	log("\e[36m[RHSIM] {rowhammer_sim.c:rowhammer_sim()}: Message: 0x");
	for (int i = 0; i < message_len; i++)
		log("%02x", message[i]);
	log("\e[39m\n");

	// Add 1 to first byte
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
	// HACK: const is no more
	uint8_t *mut_message = message;
#pragma GCC diagnostic pop
	mut_message[0] = mut_message[0] + 1;
	log("\e[36m[RHSIM] {rowhammer_sim.c:rowhammer_sim()}: Message modified\e[39m\n");

	// Print modified message
		log("\e[36m[RHSIM] {rowhammer_sim.c:rowhammer_sim()}: Message: 0x");
	for (int i = 0; i < message_len; i++)
		log("%02x", message[i]);
	log("\e[39m\n");
}