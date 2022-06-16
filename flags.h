#pragma once

// Fault flags
#define FLAGS_FAULT_PARAM_NONE 0
#define FLAGS_FAULT_PARAM_R 1
#define FLAGS_FAULT_PARAM_A 2
#define FLAGS_FAULT_PARAM_M 3
extern int fault_param;

// Mitigation flags
#define FLAGS_MIT_RAND      1 << 0 // Mitigation: Additional randomness
#define FLAGS_MIT_CHECK     1 << 1 // Mitigation: Check params during signing
extern int mitigations;