#include <utility>

#ifndef __COMMON_H_
#define __COMMON_H_

#include <gmpxx.h>
#include <vector>
#include <functional>
#include <bitset>
#include <errno.h>

// IT'S BACK, BABY
#define TRY(func)               \
    do {                        \
        auto err = (func);      \
		if (err < 0) {          \
            perror(#func);      \
            exit(EXIT_FAILURE); \
        }                       \
    } while (0)

// Like TRY, except it doesn't necessarily murder the program
#define SAFE_TRY(func)          \
    do {                        \
        auto err = (func);      \
        if (err < 0) {          \
            perror(#func);       \
            return -1;          \
        }                       \
    } while (0)

//GUESS WHAT ELSE IS BACK
struct on_scope_exit {
    typedef std::function<void()> exit_fn;
    exit_fn fn;

    explicit on_scope_exit(exit_fn &&fn) : fn(std::move(fn)) {}
    ~on_scope_exit() {
        fn();
    }
};

// Am I a horrible person for doing this? Yes. Do I care? No.
typedef mpz_class mpz;
typedef mpq_class mpq;
typedef mpf_class mpf;

mpz vector2mpz(const std::vector<uint8_t> &in);
mpz array2mpz(const uint8_t *buf, size_t len);
std::vector<uint8_t> mpz2vector(mpz in);
void mpz2array(mpz in, uint8_t *buf, size_t len);

mp_bitcnt_t mpz_log2(mpz in);
mpz modpow(mpz x, mpz y, mpz m);

template<size_t N>
mpz bitset2mpz(const std::bitset<N> &in) {
	mpz ret;
	for (size_t i = 0; i < N; i ++) {
		if (in[i]) {
			mpz_setbit(ret.get_mpz_t(), i);
		} else {
			mpz_clrbit(ret.get_mpz_t(), i);
		}
	}
	return ret;
}

template<size_t N>
std::bitset<N> mpz2bitset(mpz in) {
	std::bitset<N> ret;
	for (size_t i = 0; i < N; i ++) {
		if (mpz_tstbit(in.get_mpz_t(), i)) {
			ret[i] = 1;
		}
	}
	return ret;
}

#endif
