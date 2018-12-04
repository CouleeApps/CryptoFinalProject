#include <sys/select.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../../ssl/ssl.h"

int main(int argc, char **argv) {
	if (argc != 3) {
		fprintf(stderr, "Usage: <address> <algorithm type, 0=rsa, 1=blum-goldwasser, 2=paillier>\n");
		return EXIT_FAILURE;
	}

	AlgorithmType protocol = (AlgorithmType) atoi(argv[2]);

	int sd;
	sockaddr_in addr;
	socklen_t len;
	TRY(sd = socket(AF_INET, SOCK_STREAM, 0));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(argv[1]);
	addr.sin_port = htons(9711);
	len = sizeof(addr);

	on_scope_exit sd_closer([sd]{
		close(sd);
	});

	ssl_session session;
	std::vector<AlgorithmType> algs = { protocol };

	int rc = ssl_connect(sd, (sockaddr *) &addr, len, &session, algs);
	if (rc != 0) {
		perror("connect");
		return EXIT_FAILURE;
	}

	//Now try to get data until the client is done
	while (true) {
		fd_set fds;
		int max_fd = sd;
		FD_ZERO(&fds);
		FD_SET(sd, &fds);
		FD_SET(fileno(stdin), &fds);

		TRY(select(max_fd + 1, &fds, NULL, NULL, NULL));

		if (FD_ISSET(sd, &fds)) {
			//Resieved data from surfer! Butter except it
			char buf[1024];
			ssize_t rcvd;

			TRY(rcvd = ssl_recv(sd, buf, 1024, &session));
			if (rcvd == 0) {
				//Closed!
				return 0;
			}
			buf[rcvd] = 0;

			//Got some data, print it!
			fwrite(buf, 1, rcvd, stdout);
		} else if (FD_ISSET(fileno(stdin), &fds)) {
			//Got stdin data, better send it
			char buf[1024];
			char *data = fgets(buf, 1024, stdin);

			if (data == nullptr && feof(stdin)) {
				//Ctrl+D
				return 0;
			}
			if (data == nullptr) {
				perror("fgets");
				return 1;
			}

			//Now send!
			TRY(ssl_send(sd, buf, strlen(data), &session));
		}
	}

	return 0;
}
