#include "common.h"

mpz vector2mpz(const std::vector<uint8_t> &in) {
    mpz rop;
    mpz_import(rop.get_mpz_t(), in.size(), -1, 1, -1, 0, in.data());
    return rop;
}

mpz array2mpz(const uint8_t *buf, size_t len) {
    mpz rop;
    mpz_import(rop.get_mpz_t(), len, -1, 1, -1, 0, buf);
    return rop;
}

std::vector<uint8_t> mpz2vector(mpz in) {
    size_t count = 0;
    uint8_t *buf = (uint8_t *) mpz_export(NULL, &count, -1, 1, -1, 0, in.get_mpz_t());
    std::vector<uint8_t> out(count);

    for (size_t i = 0; i < count; i++) {
        out[i] = buf[i];
    }

    return out;
}

mp_bitcnt_t mpz_log2(mpz in) {
	//sizeinbase is basically log2+1
    return mpz_sizeinbase(in.get_mpz_t(), 2) - 1;
}

mpz modpow(mpz x, mpz y, mpz m) {
    mpz rop;
    mpz_powm(rop.get_mpz_t(), x.get_mpz_t(), y.get_mpz_t(), m.get_mpz_t());
    return rop;
}

void mpz2array(mpz in, uint8_t *buf, size_t len) {
    size_t count = 0;
    uint8_t *out = (uint8_t *) mpz_export(NULL, &count, -1, 1, -1, 0, in.get_mpz_t());
    memcpy(buf, out, std::min(len, count));

}
