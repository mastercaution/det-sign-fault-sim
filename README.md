This is part of a small university project to evaluate possible mitigations against fault attacks on deterministic signature schemes. The attacks we simulate are explained in the following paper: 

> Attacking Deterministic Signature Schemes Using Fault Attacks (EusoSP '18): https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8406609&tag=1

## Build Instructions
### Clone Repo
```
git clone --recurse-submodules https://github.com/mastercaution/det-sign-fault-sim.git
```
### Build modified OpenSSL
1. Build Rowhammer simulator lib
    ```
    make sim
    ```
2. Patch OpenSSL source files for the simulator:
    ```
    cd openssl
    git apply ../ossl_ed25519_rowhammer_sim.patch
    ```
3. Build OpenSSL and linking the sim
    1. `LDFLAGS+="../rowhammer_sim.a" ./Configure`
    2. `make`

> CAUTION: This is now a modified version of OpenSSL! Do __not__ install it anywhere and __only__ use is for this simulator!

### Build attacks
It's simply
```
make
```

## Attack Information
### OSSL Ed25519 Attack (`ossl_ed25519_attack`)
This is a simulated fault attack on OpenSSL Ed25519 signing, which forces the signing algorithm to use a nonce twice for different messages.