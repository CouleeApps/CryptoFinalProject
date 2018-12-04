#include "common.h"
#include "rsa.h"

std::vector<uint8_t> rsa_encrypt(std::vector<uint8_t> msg, rsa_pubkey key) {
    mpz n = array2mpz(key.n, RSA_KEY_LENGTH),
        e = array2mpz(key.e, RSA_KEY_LENGTH),
        m = vector2mpz(msg),
        c = modpow(m, e, n);

    return mpz2vector(c);
}

std::vector<uint8_t> rsa_decrypt(std::vector<uint8_t> msg, rsa_privkey key) {
    mpz n = array2mpz(key.n, RSA_KEY_LENGTH),
        d = array2mpz(key.d, RSA_KEY_LENGTH),
        c = vector2mpz(msg),
        m = modpow(c, d, n);

    return mpz2vector(m);
}
