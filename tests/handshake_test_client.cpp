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
    if (argc != 2) {
        fprintf(stderr, "Usage: <algorithm type, 0=rsa, 1=blum-goldwasser, 2=paillier>\n");
        return EXIT_FAILURE;
    }

    AlgorithmType protocol = (AlgorithmType) atoi(argv[1]);

	int sd;
	sockaddr_in addr;
	socklen_t len;
	TRY(sd = socket(AF_INET, SOCK_STREAM, 0));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(6778);
	len = sizeof(addr);

	ssl_session session;
	std::vector<AlgorithmType> algs = { protocol };

	int rc = ssl_connect(sd, (sockaddr *) &addr, len, &session, algs);
	if (rc != 0) {
		perror("connect");
		return EXIT_FAILURE;
	}
	printf("Client successfully connected\nKey is: ");
	for (int i = 0; i < 16; i++) {
		printf("%hhx", session.key[i]);
	}
	printf("\n");

	const char *msg = "Hello, SSL!";

	char rcv_buf[256];

	rc = ssl_recv(sd, (void *)rcv_buf, sizeof(rcv_buf), &session);
	if (rc < 0) {
		perror("Rip child recv");
		return EXIT_FAILURE;
	}

	printf("Client received msg: %s\n", rcv_buf);

	rc = ssl_send(sd, (void *)msg, strlen(msg)+1, &session);
	if (rc < 0) {
		perror("Rip child send");
		return EXIT_FAILURE;
	}
	printf("Client sent msg: %s\n", msg);

    return 0;
}
