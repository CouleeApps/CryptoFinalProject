#include "paillier.h"

std::vector<uint8_t> pa_encrypt(std::vector<uint8_t> vmsg, pa_pubkey &key) {
    mpz n = array2mpz(key.n, PA_KEY_LENGTH),
        g = array2mpz(key.g, PA_KEY_LENGTH);

    // set up the random number generator
    gmp_randclass rgen(gmp_randinit_mt);
    rgen.seed(time(NULL));

    mpz m = vector2mpz(vmsg);
    mpz r;

    bool r_found = false;

    // Generate random numbers until we find an r s.t. gcd(r, n) == 1
    // Usually it's the first one generated, so this doesn't take too long
    while (!r_found) {
        r = rgen.get_z_range(n);
        if (gcd(r, n) == 1) r_found = true;
    }
    
    // Pre-compute n^2
    mpz n_2;
    mpz_pow_ui(n_2.get_mpz_t(), n.get_mpz_t(), 2);

    
    // Compute c=(g^m)*(r^n) mod n^2
    mpz c, i1, i2;
    mpz_powm(i1.get_mpz_t(), g.get_mpz_t(), m.get_mpz_t(), n_2.get_mpz_t());
    mpz_powm(i2.get_mpz_t(), r.get_mpz_t(), n.get_mpz_t(), n_2.get_mpz_t());
    c = (i1 * i2) % n_2;

    return mpz2vector(c);
}

std::vector<uint8_t> pa_decrypt(std::vector<uint8_t> vmsg, pa_privkey &key) {
    mpz c = vector2mpz(vmsg),
        n = array2mpz(key.n, PA_KEY_LENGTH),
        car_n = array2mpz(key.car_n, PA_KEY_LENGTH),
        mu = array2mpz(key.mu, PA_KEY_LENGTH);
    
    
    // Pre-compute n^2
    mpz n_2;
    mpz_pow_ui(n_2.get_mpz_t(), n.get_mpz_t(), 2);
    
    // Compute m = L(c^(car_n) mod n^2) * mu mod n
    mpz m, i1;
    mpz_powm(i1.get_mpz_t(), c.get_mpz_t(), car_n.get_mpz_t(), n_2.get_mpz_t());
    m = (((i1 - 1) / n) * mu) % n;

    return mpz2vector(m);
}
