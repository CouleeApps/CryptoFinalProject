#include <stdio.h>
#include <iostream>
#include <string>
#include <vector>

#include "../ssl/common.h"
#include "../ssl/rsa.h"

int main(int argc, char **argv) {
    std::string msg = "ABCDEFGH";

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pub key file> <priv key file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    FILE *pubkey_f  = fopen(argv[1], "r"),
         *privkey_f = fopen(argv[2], "r");

    uint8_t n[RSA_KEY_LENGTH], e[RSA_KEY_LENGTH], d[RSA_KEY_LENGTH];

    fread(n, RSA_KEY_LENGTH, 1, pubkey_f);
    fread(e, RSA_KEY_LENGTH, 1, pubkey_f);
    fread(d, RSA_KEY_LENGTH, 1, privkey_f);

    fclose(pubkey_f);
    fclose(privkey_f);
    
    rsa_pubkey pubkey(n, e);
    rsa_privkey privkey(n, d);

    std::cout << "n: " << array2mpz(n, RSA_KEY_LENGTH) << std::endl;
    std::cout << "e: " << array2mpz(e, RSA_KEY_LENGTH) << std::endl;
    std::cout << "d: " << array2mpz(d, RSA_KEY_LENGTH) << std::endl;
    std::cout << "m: " << msg << std::endl;

    std::vector<uint8_t> vmsg;
    for (size_t i = 0; i < msg.size(); i++) {
        vmsg.push_back(msg[i]);
    }

    std::vector<uint8_t> ctext = rsa_encrypt(vmsg, pubkey);
    
    std::cout << "C(m) = {";
    for (size_t i = 0; i < ctext.size(); i++) {
        printf("0x%02hhX%s", ctext[i], i < (ctext.size() - 1) ? ", ": "");
    }
    std::cout << "}" << std::endl;

    std::vector<uint8_t> vmsg2 = rsa_decrypt(ctext, privkey);

    std::string msg2;
    for (size_t i = 0; i < vmsg2.size(); i++) {
        msg2.push_back(vmsg2[i]);
    }

    printf("D(C(m)) = %s\n", msg2.c_str());

    return 0;
}
