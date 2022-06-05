#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include "rowhammer_sim.h"

// static const uint8_t kmsg[] = {1, 2, 3, 4}; Cannot be used because it lands in .rodata section where modification is prohibited
uint8_t kmsg[] = {1, 2, 3, 4};

int main(int arc, char *argv[])
{
	// Manipulate message
	puts("Calling attack twice");
	rowhammer_sim_attack(kmsg, sizeof(kmsg));
	rowhammer_sim_attack(kmsg, sizeof(kmsg));
}