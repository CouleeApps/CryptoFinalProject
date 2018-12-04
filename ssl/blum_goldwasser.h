#include <vector>
#include <math.h>
#include "common.h"

#define BG_KEY_LENGTH 128

class bg_pubkey {
public:
	uint8_t n[BG_KEY_LENGTH * 2];

	bg_pubkey() {}
	bg_pubkey(uint8_t *n_) {
		memcpy(n, n_, sizeof(n));
	}
};

class bg_privkey {
public:
	uint8_t p[BG_KEY_LENGTH];
	uint8_t q[BG_KEY_LENGTH];

	bg_privkey() {}
	bg_privkey(uint8_t *p_, uint8_t *q_) {
		memcpy(p, p_, sizeof(uint8_t) * BG_KEY_LENGTH);
		memcpy(q, q_, sizeof(uint8_t) * BG_KEY_LENGTH);
	}
};

std::vector<uint8_t> bg_encrypt(const std::vector<uint8_t> &vmsg, const bg_pubkey &key);
std::vector<uint8_t> bg_decrypt(const std::vector<uint8_t> &msg, const bg_privkey &key);