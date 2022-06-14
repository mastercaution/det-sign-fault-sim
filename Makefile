.PHONY: openssl sim clean clean_all

CFLAGS += -O2
LDFLAGS +=

RHSIM_CFLAGS += $(CFLAGS) -c
RHSIM_LDFLAGS += $(LDFLAGS)
RHSIM_DEFS += -DRHSIM_VERBOSE

ATCK_CFLAGS += $(CFLAGS)
ATCK_LDFLAGS += $(LDFLAGS) -I./openssl/include -lgmp
ATCK_DEFS +=

all: ossl_ed25519_attack

prepare: rowhammer_sim.a pretty_print.a
rowhammer_sim.a: rowhammer_sim.c
	$(CC) $(RHSIM_CFLAGS) $(RHSIM_DEFS) -o $@ $^ $(RHSIM_LDFLAGS)

rowhammer_sim_example: rowhammer_sim_example.c rowhammer_sim.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

pretty_print.a: pretty_print.c
	$(CC) $(RHSIM_CFLAGS) -o $@ $^ $(ATCK_LDFLAGS)

ossl_ed25519_attack: ossl_ed25519_attack.c pretty_print.a rowhammer_sim.a openssl/libssl.a openssl/libcrypto.a
	$(CC) $(ATCK_CFLAGS) $(ATCK_DEFS) -o $@ $^ $(ATCK_LDFLAGS)

openssl/libssl.a: openssl
openssl/libcrypto.a: openssl
openssl: openssl/Makefile prepare
	$(MAKE) -C openssl build_libs

openssl/Makefile:
	cd openssl && CPPFLAGS+=-DROWHAMMER_SIM ./Configure && cd ..

clean:
	$(RM) -rf ossl_ed25519_attack rowhammer_sim_example rowhammer_sim.a pretty_print.a

clean_all: clean
	$(MAKE) -C openssl clean