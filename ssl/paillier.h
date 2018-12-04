#ifndef __PAILLIER_H_
#define __PAILLIER_H_

#include <stdint.h>
#include <string.h>
#include <vector>

#include "common.h"

#define PA_KEY_LENGTH 128

class pa_pubkey {
public:
    uint8_t n[PA_KEY_LENGTH], g[PA_KEY_LENGTH];
    pa_pubkey() {}
    pa_pubkey(uint8_t *n_, uint8_t *g_) {
        memcpy(n, n_, PA_KEY_LENGTH);
        memcpy(g, g_, PA_KEY_LENGTH);
    }
};

class pa_privkey {
public:
    uint8_t n[PA_KEY_LENGTH], car_n[PA_KEY_LENGTH], mu[PA_KEY_LENGTH];
    pa_privkey() {}
    pa_privkey(uint8_t *n_, uint8_t *car_n_, uint8_t *mu_) {
        memcpy(n, n_, PA_KEY_LENGTH);
        memcpy(car_n, car_n_, PA_KEY_LENGTH);
        memcpy(mu, mu_, PA_KEY_LENGTH);
    }
};

std::vector<uint8_t> pa_encrypt(std::vector<uint8_t> msg, pa_pubkey &key);
std::vector<uint8_t> pa_decrypt(std::vector<uint8_t> msg, pa_privkey &key);

#endif
