#include <iostream>
#include <stdio.h>
#include <string>
#include <vector>

#include "../ssl/common.h"
#include "../ssl/paillier.h"

int main(int argc, char **argv) {
    std::string msg = "ABCDEFGH";

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pub key file> <priv key file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *pubkey_f = fopen(argv[1], "r"),
         *privkey_f = fopen(argv[2], "r");

    uint8_t n[PA_KEY_LENGTH], g[PA_KEY_LENGTH], car_n[PA_KEY_LENGTH], mu[PA_KEY_LENGTH];

    fread(n, PA_KEY_LENGTH, 1, pubkey_f);
    fread(g, PA_KEY_LENGTH, 1, pubkey_f);
    fread(car_n, PA_KEY_LENGTH, 1, privkey_f);
    fread(mu, PA_KEY_LENGTH, 1, privkey_f);

    fclose(pubkey_f);
    fclose(privkey_f);

    pa_pubkey pubkey(n, g);
    pa_privkey privkey(n, car_n, mu);

    std::cout << "n: " << array2mpz(n, PA_KEY_LENGTH) << std::endl;
    std::cout << "g: " << array2mpz(g, PA_KEY_LENGTH) << std::endl;
    std::cout << "lambda(n): " << array2mpz(car_n, PA_KEY_LENGTH) << std::endl;
    std::cout << "mu: " << array2mpz(mu, PA_KEY_LENGTH) << std::endl;

    std::vector<uint8_t> vmsg;
    for (size_t i = 0; i < msg.size(); i++) {
        vmsg.push_back(msg[i]);
    }

    std::cout << "m = " << msg << std::endl;

    std::vector<uint8_t> ctext = pa_encrypt(vmsg, pubkey);
    std::cout << "C(m) = {";
    for(size_t i = 0; i < ctext.size(); i++) {
        printf("0x%02hhX%s", ctext[i], i < (ctext.size() - 1) ? ", " : "");
        
    }

    std::cout << "}" << std::endl;

    std::vector<uint8_t> vmsg2 = pa_decrypt(ctext, privkey);

    std::string msg2;
    for (size_t i = 0; i < vmsg2.size(); i++) {
        msg2.push_back(vmsg2[i]);
    }

    printf("D(C(m)) = %s\n", msg2.c_str());

    return 0;
}
