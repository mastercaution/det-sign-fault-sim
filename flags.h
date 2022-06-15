#pragma once

// Fault flags
#define FLAGS_FAULT_PARAM_NONE 0
#define FLAGS_FAULT_PARAM_R 1
#define FLAGS_FAULT_PARAM_A 2
#define FLAGS_FAULT_PARAM_M 3
extern int fault_param;

// Mitigation flags
extern int mit_rand;		// Mitigation: Additional randomness