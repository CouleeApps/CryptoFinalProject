
#include <string>
#include <fstream>
#include <iostream>
#include <assert.h>
#include "../ssl/blum_goldwasser.h"

int main(int argc, const char **argv) {
	if (argc != 3) {
		fprintf(stderr, "Usage: %s <pub key file> <priv key file>\n", argv[0]);
		return EXIT_FAILURE;
	}

	FILE *pubkey_f = fopen(argv[1], "r"),
	     *privkey_f = fopen(argv[2], "r");

	uint8_t p[BG_KEY_LENGTH], q[BG_KEY_LENGTH], n[BG_KEY_LENGTH * 2];

	fread(n, BG_KEY_LENGTH * 2, 1, pubkey_f);
	fread(p, BG_KEY_LENGTH, 1, privkey_f);
	fread(q, BG_KEY_LENGTH, 1, privkey_f);

	fclose(pubkey_f);
	fclose(privkey_f);

	bg_privkey priv{
			p, q
	};
	bg_pubkey pub = {
			n
	};

	std::cout << "p: " << array2mpz(p, BG_KEY_LENGTH) << std::endl;
	std::cout << "q: " << array2mpz(q, BG_KEY_LENGTH) << std::endl;
	std::cout << "n: " << array2mpz(n, BG_KEY_LENGTH * 2) << std::endl;

	mpz m = 0x123456789abcdef0;

	std::cout << "m = " << m << std::endl;

	auto c = bg_encrypt(mpz2vector(m), pub);
	std::cout << "C(m) = {";
	for (uint64_t i = 0; i < c.size(); i ++) {
		printf("0x%02hhX", c[i]);
		if (i < (c.size() - 1))
			std::cout << ", ";
	}
	std::cout << "};" << std::endl;

	auto dec = vector2mpz(bg_decrypt(c, priv));
	std::cout << "D(C(m)) = " << dec << std::endl;
	assert(dec == m);

	return 0;
}
