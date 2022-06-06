.PHONY: openssl sim clean clean_all

CFLAGS += -O2
LDFLAGS +=

RHSIM_CFLAGS += $(CFLAGS) -c
RHSIM_LDFLAGS += $(LDFLAGS)
RHSIM_DEFS += -DRHSIM_VERBOSE

ATCK_CFLAGS += $(CFLAGS)
ATCK_LDFLAGS += $(LDFLAGS) -I./openssl/include
ATCK_DEFS += -DATCK_VERBOSE

all: ossl_ed25519_attack

sim: rowhammer_sim.a
rowhammer_sim.a: rowhammer_sim.c
	$(CC) $(RHSIM_CFLAGS) $(RHSIM_DEFS) -o $@ $^ $(RHSIM_LDFLAGS)

rowhammer_sim_example: rowhammer_sim_example.c rowhammer_sim.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

ossl_ed25519_attack: ossl_ed25519_attack.c rowhammer_sim.a openssl/libssl.a openssl/libcrypto.a
	$(CC) $(ATCK_CFLAGS) $(ATCK_DEFS) -o $@ $^ $(ATCK_LDFLAGS)

openssl/libssl.a: openssl
openssl/libcrypto.a: openssl
openssl:
	$(MAKE) -C openssl

clean:
	$(RM) -rf ossl_ed25519_attack rowhammer_sim_example rowhammer_sim.a

clean_all: clean
	$(MAKE) -C openssl clean