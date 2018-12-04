#ifndef __RSA_H_
#define __RSA_H_

#include <vector>
#include <stdint.h>

#define RSA_KEY_LENGTH 128

class rsa_pubkey {
public:
    uint8_t n[RSA_KEY_LENGTH], e[RSA_KEY_LENGTH];
    rsa_pubkey() {}
    rsa_pubkey(uint8_t *n_, uint8_t *e_) {
        memcpy(n, n_, RSA_KEY_LENGTH);
        memcpy(e, e_, RSA_KEY_LENGTH);
    }
};

class rsa_privkey {
public:
    uint8_t n[RSA_KEY_LENGTH], d[RSA_KEY_LENGTH];
    rsa_privkey() {}
    rsa_privkey(uint8_t *n_, uint8_t *d_) {
        memcpy(n, n_, RSA_KEY_LENGTH);
        memcpy(d, d_, RSA_KEY_LENGTH);
    }
};

std::vector<uint8_t> rsa_encrypt(std::vector<uint8_t> msg, rsa_pubkey key);
std::vector<uint8_t> rsa_decrypt(std::vector<uint8_t> msg, rsa_privkey key);

#endif
