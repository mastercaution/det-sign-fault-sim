#pragma once
#include <stdint.h>
#include <stddef.h>

void rowhammer_sim_attack(const uint8_t *message, size_t message_len);
void rowhammer_sim(const uint8_t *message, size_t message_len);
void rowhammer_sim_inc();