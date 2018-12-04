#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string>
#include <vector>

#include "../ssl/common.h"
#include "../ssl/paillier.h"
#include "../ssl/ssl.h"

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr, "Usage: %s <rsapubkey> <rsaprivkey> <bgpubkey> <bgprivkey> <ppubkey> <pprivkey>\n", argv[0]);
        return EXIT_FAILURE;
    }

    ssl_keychain keychain;

    {
        FILE *pubkey_f = fopen(argv[1], "r"),
            *privkey_f = fopen(argv[2], "r");
        
        if (!pubkey_f || !privkey_f) {
            perror("fopen");
            return EXIT_FAILURE;
        }

        uint8_t n[RSA_KEY_LENGTH], e[RSA_KEY_LENGTH], d[RSA_KEY_LENGTH];

        fread(n, RSA_KEY_LENGTH, 1, pubkey_f);
        fread(e, RSA_KEY_LENGTH, 1, pubkey_f);
        fread(d, RSA_KEY_LENGTH, 1, privkey_f);

        fclose(pubkey_f);
        fclose(privkey_f);

        keychain.rsapubkey = rsa_pubkey(n, e);
        keychain.rsaprivkey = rsa_privkey(n, d);
        keychain.supported_algs.push_back(AlgorithmType::rsa);
    }

	{
		FILE *pubkey_f = fopen(argv[3], "r"),
				*privkey_f = fopen(argv[4], "r");

		if (!pubkey_f || !privkey_f) {
			perror("fopen");
			return EXIT_FAILURE;
		}

		uint8_t p[BG_KEY_LENGTH], q[BG_KEY_LENGTH], n[BG_KEY_LENGTH * 2];

		fread(n, BG_KEY_LENGTH * 2, 1, pubkey_f);
		fread(p, BG_KEY_LENGTH, 1, privkey_f);
		fread(q, BG_KEY_LENGTH, 1, privkey_f);

		fclose(pubkey_f);
		fclose(privkey_f);

		keychain.bgpubkey = bg_pubkey(n);
		keychain.bgprivkey = bg_privkey(p, q);
		keychain.supported_algs.push_back(AlgorithmType::blum_goldwasser);
	}

    {
        FILE *pubkey_f = fopen(argv[5], "r"),
            *privkey_f = fopen(argv[6], "r");
        
        if (!pubkey_f || !privkey_f) {
            perror("fopen");
            return EXIT_FAILURE;
        }

        uint8_t n[PA_KEY_LENGTH], g[PA_KEY_LENGTH], car_n[PA_KEY_LENGTH], mu[PA_KEY_LENGTH];

        fread(n, PA_KEY_LENGTH, 1, pubkey_f);
        fread(g, PA_KEY_LENGTH, 1, pubkey_f);
        fread(car_n, PA_KEY_LENGTH, 1, privkey_f);
        fread(mu, PA_KEY_LENGTH, 1, privkey_f);

        fclose(pubkey_f);
        fclose(privkey_f);

        keychain.papubkey = pa_pubkey(n, g);
        keychain.paprivkey = pa_privkey(n, car_n, mu);
        keychain.supported_algs.push_back(AlgorithmType::paillier);
    }

    int sd;
    sockaddr_in addr;
    socklen_t len;

    TRY(sd = socket(AF_INET, SOCK_STREAM, 0));

    memset(&addr.sin_addr, 0, sizeof(addr.sin_addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(6778);
    len = sizeof(addr);
    TRY(bind(sd, (sockaddr *) &addr, len));
    TRY(listen(sd, 8));

    sockaddr_in new_sock;
    socklen_t new_len = sizeof(new_sock);

    ssl_session session;

    int clientsd = ssl_accept(sd, (sockaddr *) &addr, &new_len, &session, &keychain);
    if (clientsd < 0) {
        perror("accept");
        return EXIT_FAILURE;
    }


    printf("Server succesfully connected\nKey is: ");
    for (int i = 0; i < 16; i++) {
        printf("%hhx", session.key[i]);
    }
    printf("\n");

    const char *msg = "Let's have a party!";

    int rc = ssl_send(clientsd, (void *)msg, strlen(msg)+1, &session);
    if (rc < 0) {
        perror("Rip parent send");
        return EXIT_FAILURE;
    }
    printf("Server sent msg: %s\n", msg);

    char rcv_buf[256];

    rc = ssl_recv(clientsd, (void *)rcv_buf, sizeof(rcv_buf), &session);
    if (rc < 0) {
        perror("Rip parent recv");
        return EXIT_FAILURE;
    }
    printf("Server received msg: %s\n", rcv_buf);

    return 0;
}
