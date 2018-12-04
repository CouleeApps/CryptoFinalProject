#include "hmac.h"

std::vector<uint8_t> H(std::vector<uint8_t> m) {
	std::vector<uint8_t> hashed(SHA1_RESULT_SIZE);
	HASH_FN(hashed.data(), m.data(), m.size());
	return hashed;
}

std::vector<uint8_t> hmac(const std::vector<uint8_t> &K, const std::vector<uint8_t> &m) {
	std::vector<uint8_t> K_prime;
	if (K.size() > BLOCK_SIZE) {
		K_prime = H(K);
	} else if (K.size() < BLOCK_SIZE) {
		//Pad out to BLOCK_SIZE bytes with zeroes
		K_prime = K;
		K_prime.resize(BLOCK_SIZE, 0);
	} else {
		K_prime = K;
	}

	std::vector<uint8_t> opad, ipad;
	for (uint8_t byte : K_prime) {
		opad.push_back(byte ^ 0x5c);
		ipad.push_back(byte ^ 0x36);
	}

	std::vector<uint8_t> idat = ipad;
	std::copy(m.begin(), m.end(), std::back_inserter(idat));
	auto ihash = H(idat);

	std::vector<uint8_t> odat = opad;
	std::copy(ihash.begin(), ihash.end(), std::back_inserter(odat));

	return H(odat);
}
