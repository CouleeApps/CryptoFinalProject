#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include "handlers.h"
#include "../../ssl/ssl.h"

// Yay, global state. Everyone's favorite.
std::string pass;
bool op_allowed = false;
std::list<User *> users;
std::mutex users_mutex;
std::map<std::string, Channel> channels;
std::mutex channels_mutex;

// Clients are handled by individual threads
void thread_handler(int sd, ssl_session session) {
    char buf[1024], *saveptr;
    User *user = new User(sd, session);
    {
        std::lock_guard<std::mutex> g(users_mutex);
        users.push_front(user);
    }

    int rc;
    char *tok;
    std::string command;
    TRY(rc = ssl_recv(sd, buf, 1024, &session));
    if (rc == 0) {
        goto done;
    }

    buf[rc - 1] = '\0';
    tok = strtok_r(buf, " ", &saveptr);
    command = std::string(tok ? tok : "");
    if (command == "USER") {
        user_handler(user, &saveptr);
    } else {
        ssl_dprintf(&user->session, user->sd, "Invalid command, please identify yourself with USER\n");
        goto done;
    }

    for (;;) {
        TRY(rc = ssl_recv(sd, buf, 1024, &session));
        if (rc == 0) {
            break;
        }
        // Chop off the trailing newline
        buf[rc - 1] = '\0';
        tok = strtok_r(buf, " ", &saveptr);
        command = std::string(tok ? tok : "");
        if (command == "USER") {
            user_handler(user, &saveptr);
        }

        if (command == "LIST") {
            list_handler(user, &saveptr);
        } else if (command == "JOIN") {
            join_handler(user, &saveptr);
        } else if (command == "PART") {
            part_handler(user, &saveptr);
        } else if (command == "OPERATOR") {
            operator_handler(user, &saveptr);
        } else if (command == "KICK") {
            kick_handler(user, &saveptr);
        } else if (command == "PRIVMSG") {
            privmsg_handler(user, &saveptr);
        } else if (command == "QUIT") {
            quit_handler(user, &saveptr);
            break;
        }
    }
    if (user->registered) {
        //If we didn't QUIT make sure we still leave our channels or we'll leave dangling
        // pointers all over the place
        quit_handler(user, NULL);
    }

done:
    close (sd);
    delete user;
}

int main(int argc, char **argv) {
    int sd;
    sockaddr_in6 addr;
    socklen_t len;
    ssl_keychain keychain;

    // Parse the args
    if (argc == 2) {
        if (strncmp(argv[1], "--opt-pass=", 11) == 0) {
            op_allowed = true;
            pass = std::string(argv[1] + 11);
        }
    } else if (argc > 2) {
        fprintf(stderr, "ERROR: Invalid args\n");
    }

    // Try and read our keys
   
    // RSA 
    FILE *rsapubkey_f = fopen("rsapubkey", "r"),
         *rsaprivkey_f = fopen("rsaprivkey", "r");
    
    if (rsapubkey_f && rsaprivkey_f) {
        uint8_t n[RSA_KEY_LENGTH], e[RSA_KEY_LENGTH], d[RSA_KEY_LENGTH];

        fread(n, RSA_KEY_LENGTH, 1, rsapubkey_f);
        fread(e, RSA_KEY_LENGTH, 1, rsapubkey_f);
        fread(d, RSA_KEY_LENGTH, 1, rsaprivkey_f);

        fclose(rsapubkey_f);
        fclose(rsaprivkey_f);

        keychain.rsapubkey = rsa_pubkey(n, e);
        keychain.rsaprivkey = rsa_privkey(n, d);
        keychain.supported_algs.push_back(AlgorithmType::rsa);    
    }
    
    // Blum-Goldwasser
    FILE *bgpubkey_f = fopen("bgpubkey", "r"),
         *bgprivkey_f = fopen("bgprivkey", "r");
    
    if (bgpubkey_f && bgprivkey_f) {
        uint8_t n[BG_KEY_LENGTH * 2], p[BG_KEY_LENGTH], q[BG_KEY_LENGTH];

        fread(n, BG_KEY_LENGTH * 2, 1, bgpubkey_f);
        fread(p, BG_KEY_LENGTH, 1, bgprivkey_f);
        fread(q, BG_KEY_LENGTH, 1, bgprivkey_f);

        fclose(bgpubkey_f);
        fclose(bgprivkey_f);

        keychain.bgpubkey = bg_pubkey(n);
        keychain.bgprivkey = bg_privkey(p, q);
        keychain.supported_algs.push_back(AlgorithmType::blum_goldwasser);    
    }

    // Paillier
    FILE *papubkey_f = fopen("papubkey", "r"),
         *paprivkey_f = fopen("paprivkey", "r");
    
    if (papubkey_f && paprivkey_f) {
        uint8_t n[PA_KEY_LENGTH], g[PA_KEY_LENGTH], car_n[PA_KEY_LENGTH], mu[PA_KEY_LENGTH];

        fread(n, PA_KEY_LENGTH, 1, papubkey_f);
        fread(g, PA_KEY_LENGTH, 1, papubkey_f);
        fread(car_n, PA_KEY_LENGTH, 1, paprivkey_f);
        fread(mu, PA_KEY_LENGTH, 1, paprivkey_f);

        fclose(papubkey_f);
        fclose(paprivkey_f);

        keychain.papubkey = pa_pubkey(n, g);
        keychain.paprivkey = pa_privkey(n, car_n, mu);
        keychain.supported_algs.push_back(AlgorithmType::paillier);    
    }

    // If we have no keys, stop. We need keys.
    if (keychain.supported_algs.size() == 0) {
        fprintf(stderr, "ERROR: No public/private keys were found\n");
        return EXIT_FAILURE;
    }

    // Start TCP socket boilerplate
    TRY(sd = socket(AF_INET6, SOCK_STREAM, 0));

    //Using v6 lets us accept both v4 and v6 at the same time
    memset(&addr.sin6_addr, 0, sizeof(addr.sin6_addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(9711);
    len = sizeof(addr);

    TRY(bind(sd, (sockaddr *) &addr, len));
    TRY(listen(sd, 8));
    // End TCP socket boilerplate

    // Handle incoming connections until something breaks or we're killed
    for (;;) {
        sockaddr_in6 new_sock;
        socklen_t new_len = sizeof(new_sock);
        ssl_session new_session;

        int new_sd = ssl_accept(sd, (struct sockaddr *) &addr, &new_len, &new_session, &keychain);
        if (new_sd < 0) {
            if (errno == EINTR || errno == EPROTO) {
                continue;
            }
            perror("ssl_accept");
            exit(EXIT_FAILURE);
        }
        std::thread(thread_handler, new_sd, new_session).detach();
    }

    return 0;
}
