#ifndef __SSL_H_
#define __SSL_H_

#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "paillier.h"
#include "rsa.h"
#include "aes.h"
#include "blum_goldwasser.h"

enum AlertLevel : uint8_t {
    warning = 1, fatal = 2  
};

enum AlertDescription : uint8_t {
    close_notify = 0, unexpected_message = 10, bad_record_mac = 20,
    handshake_failure = 40, no_certificate = 41, bad_certificate = 42,
    illegal_parameter = 47
};

struct Alert {
    AlertLevel level;
    AlertDescription description;
};

enum HandshakeType : uint8_t { 
    hello_request = 0, client_hello = 1, server_hello = 2,
    server_key_exchange = 12, server_hello_done = 14,
    client_key_exchange = 16, finished = 20
};

enum AlgorithmType : uint8_t {
    rsa = 0, blum_goldwasser = 1, paillier = 2
};
/*
struct Random {
    uint32_t gmt_unix_time;
    uint8_t random_bytes[8];
};
*/
// I blame the RFC for this mess
struct Handshake {
    HandshakeType msg_type;
    uint16_t len;
    union {
        struct {} HelloRequest;
        struct {
            // uint8_t session_id[16];   // Might choose to add this later
            AlgorithmType algorithms[1]; // This would be a flexible array, but the struct is empty
        } ClientHello;
        struct {
            // uint8_t session_id[16];
            AlgorithmType cipher_suite;
        } ServerHello;
        struct {
            AlgorithmType key_exchange_algorithm;
            union {
                rsa_pubkey rsa_params;
                bg_pubkey bg_params; 
                pa_pubkey paillier_params;
            };
        } ServerKeyExchange;
        struct {} ServerHelloDone;
        struct {
            uint8_t encrypted_key[1];    // Same deal with the flexible arrays
        } ClientKeyExchange;
        struct {
            uint8_t sha_hash[20];
        } Finished;
    };
};

struct ssl_session {
    // uint8_t session_id[16];
    std::vector<AlgorithmType> supported_algs;
    AlgorithmType alg;
    uint8_t key[AES_KEY_LENGTH];
    pa_pubkey ppubkey;
    rsa_pubkey rsapubkey;
    bg_pubkey bgpubkey;
};

struct ssl_keychain {
    ssl_keychain() {}
    std::vector<AlgorithmType> supported_algs;
    pa_pubkey papubkey;
    pa_privkey paprivkey;
    rsa_pubkey rsapubkey;
    rsa_privkey rsaprivkey;
    bg_pubkey bgpubkey;
    bg_privkey bgprivkey;
};

int ssl_accept(int sockfd, sockaddr *addr, socklen_t *addrlen,
        ssl_session *session, ssl_keychain *keychain);

int ssl_connect(int sockfd, const sockaddr *addr, socklen_t addrlen, ssl_session *session,
        std::vector<AlgorithmType> &algorithms);

ssize_t ssl_send(int sockfd, void *buffer, size_t length, ssl_session *session);

ssize_t ssl_recv(int sockfd, void *buffer, size_t length, ssl_session *session);

#endif
