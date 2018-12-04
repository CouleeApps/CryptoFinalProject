#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>

#include "common.h"
#include "ssl.h"
#include "sha1.h"
#include "hmac.h"

void send_alert(int sockfd, AlertLevel level, AlertDescription description) {
    Alert alert = { .level = level, .description = description };
    TRY(send(sockfd, &alert, sizeof(alert), 0));
}

// Receives a handshake message, checking that it's the correct type of message
int recv_handshake_msg(int sockfd, Handshake *msg, HandshakeType msgtype, size_t len = 1024) {
    SAFE_TRY(recv(sockfd, msg, len, 0));

    if (msg->msg_type != msgtype) {
        send_alert(sockfd, AlertLevel::fatal, AlertDescription::unexpected_message);
        close(sockfd);
        // fprintf(stderr, "ERROR: recv_handshake_message wrong type\n");
        errno = EPROTO;
        return -1;
    }

    return 0;
}

// Equivalent to accept(), but secure
int ssl_accept(int sockfd, sockaddr *addr, socklen_t *addrlen,
        ssl_session *session, ssl_keychain *keychain) {
    int newsock;
    // Accept the incoming connection
    SAFE_TRY(newsock = accept(sockfd, addr, addrlen));

    uint8_t buf[1024];
    Handshake *msg = (Handshake *) &buf;
    // Receive the first packet from the client
    SAFE_TRY(recv_handshake_msg(newsock, msg, HandshakeType::client_hello));

    // Figure out which algorithm we're using based on the list the client provided and what we
    // support
    AlgorithmType *algs = new AlgorithmType[msg->len];
    memcpy(algs, msg->ClientHello.algorithms, msg->len);

    for (int i = 0; i < msg->len; i++) {
        for (auto srv_alg : keychain->supported_algs) {
            if (srv_alg == algs[i]) {
                session->alg = srv_alg;
                goto loop_exit; // Hail GOTO
            }
        }
    }

    // If we couldn't find an algorithm the client & server both support, send a fatal error
    send_alert(newsock, AlertLevel::fatal, AlertDescription::handshake_failure);
    close(newsock);
    errno = EPROTO;
    return -1;

loop_exit:
    // Send the ServerHello message
    msg->msg_type = HandshakeType::server_hello;
    msg->len = 1;
    msg->ServerHello.cipher_suite = session->alg;
    SAFE_TRY(send(newsock, msg, msg->len + 4, 0));

    // Send the ServerKeyExchange message
    
    // Switch on the algorithm type to send the correct key
    msg->msg_type = HandshakeType::server_key_exchange;
    switch (session->alg) {
        case AlgorithmType::rsa:
            msg->len = sizeof(rsa_pubkey) + 1;
            msg->ServerKeyExchange.key_exchange_algorithm = AlgorithmType::rsa;
            msg->ServerKeyExchange.rsa_params = keychain->rsapubkey;
            break;
        case AlgorithmType::blum_goldwasser:
            msg->len = sizeof(bg_pubkey) + 1;
            msg->ServerKeyExchange.key_exchange_algorithm = AlgorithmType::blum_goldwasser;
            msg->ServerKeyExchange.bg_params = keychain->bgpubkey;
            break;
        case AlgorithmType::paillier:
            msg->len = sizeof(pa_pubkey) + 1;
            msg->ServerKeyExchange.key_exchange_algorithm = AlgorithmType::paillier;
            msg->ServerKeyExchange.paillier_params = keychain->papubkey;
            break;
        default:
            close(newsock);
            errno = EINVAL;
            return -1;
    }

    SAFE_TRY(send(newsock, msg, msg->len + 4, 0));

    // Receive the encrypted session key from the client
    SAFE_TRY(recv_handshake_msg(newsock, msg, HandshakeType::client_key_exchange));

    std::vector<uint8_t> ctext, session_key;
    for (int i = 0; i < msg->len; i++) {
        ctext.push_back(msg->ClientKeyExchange.encrypted_key[i]);
    }

    // Switch on the encryption type to decrypt correctly
    switch (session->alg) {
        case AlgorithmType::rsa:
            session_key = rsa_decrypt(ctext, keychain->rsaprivkey);
            break;
        case AlgorithmType::blum_goldwasser:
	        session_key = bg_decrypt(ctext, keychain->bgprivkey);
            break;
        case AlgorithmType::paillier:
            session_key = pa_decrypt(ctext, keychain->paprivkey);
            break;
        default:
            close(newsock);
            errno = EINVAL;
            return -1;
    }

    memcpy(session->key, session_key.data(), AES_KEY_LENGTH);

    // Send our Finished message to the client
    msg->msg_type = HandshakeType::finished;
    msg->len = 20;
    uint8_t keyhash[20];
    HASH_FN(keyhash, session_key.data(), session_key.size());
    memcpy(msg->Finished.sha_hash, keyhash, 20);
    SAFE_TRY(send(newsock, msg, msg->len + 4, 0));

    // receive the client's Finished message and make sure it's all right
    SAFE_TRY(recv_handshake_msg(newsock, msg, HandshakeType::finished));
    if (memcmp(keyhash, msg->Finished.sha_hash, 20) != 0) {
        send_alert(newsock, AlertLevel::fatal, AlertDescription::illegal_parameter);
        close(newsock);
        errno = EPROTO;
        return -1;
    }

    return newsock;
}
// Equivalent to connect(), but secure
int ssl_connect(int sockfd, const sockaddr *addr, socklen_t addrlen, ssl_session *session,
        std::vector<AlgorithmType> &algorithms) {
    // Open up the connection
    SAFE_TRY(connect(sockfd, addr, addrlen));

    uint8_t buf[1024];
    Handshake *msg = (Handshake *) &buf;

    // Send the ClientHello message
    msg->msg_type = HandshakeType::client_hello;
    msg->len = algorithms.size();
    memcpy(msg->ClientHello.algorithms, algorithms.data(), msg->len);
    SAFE_TRY(send(sockfd, msg, msg->len + 4, 0));

    // Receive the ServerHello message
    SAFE_TRY(recv_handshake_msg(sockfd, msg, HandshakeType::server_hello, 5));

    // Receive the ServerKeyExchange message
    SAFE_TRY(recv_handshake_msg(sockfd, msg, HandshakeType::server_key_exchange));

    // Generate the 128-bit session key by reading from /dev/urandom
    std::vector<uint8_t> session_key(AES_KEY_LENGTH), ctext;
    int ur = open("/dev/urandom", O_RDONLY);
    read(ur, session_key.data(), AES_KEY_LENGTH);
    close(ur);
    memcpy(session->key, session_key.data(), AES_KEY_LENGTH);

    // Send the ClientKeyExchange message to the server
    msg->msg_type = HandshakeType::client_key_exchange;

    rsa_pubkey rsakey;
    bg_pubkey bgkey;
    pa_pubkey pakey;

    // Switch on the algorithm type to get the right key
    switch (msg->ServerKeyExchange.key_exchange_algorithm) {
        case AlgorithmType::rsa:
            memcpy(&rsakey, &msg->ServerKeyExchange.rsa_params, sizeof(rsa_pubkey));
            ctext = rsa_encrypt(session_key, rsakey);
            break;
        case AlgorithmType::blum_goldwasser:
            memcpy(&bgkey, &msg->ServerKeyExchange.bg_params, sizeof(bg_pubkey));
            ctext = bg_encrypt(session_key, bgkey);
            break;
        case AlgorithmType::paillier:
            memcpy(&pakey, &msg->ServerKeyExchange.paillier_params, sizeof(pa_pubkey));
            ctext = pa_encrypt(session_key, pakey);
            break;
        default:
            // fprintf(stderr, "ERROR: Bad algorithm");
            close(sockfd);
            errno = EINVAL;
            return -1;
    }

    msg->len = ctext.size();
    memcpy(msg->ClientKeyExchange.encrypted_key, ctext.data(), ctext.size());
    SAFE_TRY(send(sockfd, msg, msg->len + 4, 0));

    // Send the Finished message to the server
    msg->msg_type = HandshakeType::finished;
    msg->len = 20;
    uint8_t keyhash[20];
    HASH_FN(keyhash, session_key.data(), session_key.size());
    memcpy(msg->Finished.sha_hash, keyhash, 20);
    SAFE_TRY(send(sockfd, msg, msg->len + 4, 0));

    // receive the server's Finished message and make sure it's all right
    SAFE_TRY(recv_handshake_msg(sockfd, msg, HandshakeType::finished));
    if (memcmp(keyhash, msg->Finished.sha_hash, 20) != 0) {
        close(sockfd);
        errno = EPROTO;
        return -1;
    }

    return 0;
}

// Equivalent to send(), but secure
ssize_t ssl_send(int sockfd, void *buffer, size_t length, ssl_session *session) {
    std::vector<uint8_t> block(AES_BLOCK_SIZE);
    std::vector<uint8_t> vec_key(AES_KEY_LENGTH);
    memcpy(vec_key.data(), session->key, AES_KEY_LENGTH);

    std::vector<uint8_t> to_send;
	FILE *f = fopen("/dev/urandom", "rb");

    //First block is the length
	{
		bzero(block.data(), AES_BLOCK_SIZE);
		block[0] = length & 0xFF;
		block[1] = (length >> 8) & 0xFF;
		block[2] = (length >> 16) & 0xFF;
		block[3] = (length >> 24) & 0xFF;


		//Hash and encrypt
		auto hash = hmac(vec_key, block);
		auto enc = aes_encrypt(block.data(), session->key);
		to_send.insert(to_send.end(), enc.begin(), enc.end());
		to_send.insert(to_send.end(), hash.begin(), hash.end());
	}

    for (size_t i = 0; i < length; i += AES_BLOCK_SIZE) {
        if (i + AES_BLOCK_SIZE > length) {
            memcpy(block.data(), (uint8_t *)buffer + i, length - i);
            //Garbo the rest
	        fread(block.data() + (length - i), 1, i + AES_BLOCK_SIZE - length, f);
        } else {
            memcpy(block.data(), (uint8_t *)buffer + i, AES_BLOCK_SIZE);
        }

        //Hash and encrypt
        auto hash = hmac(vec_key, block);
        auto enc = aes_encrypt(block.data(), session->key);
        to_send.insert(to_send.end(), enc.begin(), enc.end());
        to_send.insert(to_send.end(), hash.begin(), hash.end());
    }
	fclose(f);

	ssize_t sent;
    sent = send(sockfd, to_send.data(), to_send.size(), 0);
    return sent;
}
// Equivalent to recv(), but secure
ssize_t ssl_recv(int sockfd, void *buffer, size_t length, ssl_session *session) {
	//Each block is AES_BLOCK_SIZE + SHA1_RESULT_SIZE so see how many blocks we can fit
	size_t block_size = AES_BLOCK_SIZE + SHA1_RESULT_SIZE;
	size_t max_blocks = length / block_size;

	std::vector<uint8_t> encbuf(block_size * max_blocks);

	ssize_t rcvd;
	if ((rcvd = recv(sockfd, encbuf.data(), encbuf.size(), 0)) < 0) {
		return rcvd;
	}

	//Don't want to deal with fragmenting
    assert(rcvd % block_size == 0);

    std::vector<uint8_t> vec_key(AES_KEY_LENGTH);
    memcpy(vec_key.data(), session->key, AES_KEY_LENGTH);

    std::vector<uint8_t> recv_buffer;
    size_t blocks = rcvd / block_size;
	for (size_t i = 0; i < blocks; i ++) {
	    //Take bytes off the front
	    std::vector<uint8_t> enc;
	    std::vector<uint8_t> hash;

	    enc.insert(enc.end(), encbuf.begin(), encbuf.begin() + AES_BLOCK_SIZE);
	    encbuf.erase(encbuf.begin(), encbuf.begin() + AES_BLOCK_SIZE);

	    hash.insert(hash.end(), encbuf.begin(), encbuf.begin() + SHA1_RESULT_SIZE);
	    encbuf.erase(encbuf.begin(), encbuf.begin() + SHA1_RESULT_SIZE);

	    //Decrypt encrypted stuff and check hash
	    auto dec = aes_decrypt(enc.data(), session->key);
	    auto real_hash = hmac(vec_key, dec);

	    if (real_hash != hash) {
	        //Oh no (https://i.imgur.com/YFJaGct.png)
		    errno = EPROTO;
	        return -1;
	    }

	    recv_buffer.insert(recv_buffer.end(), dec.begin(), dec.end());
	}

	size_t bytes_total = 0;
	//We could have gotten more than one message so make sure we receive as many as we can
	while (!recv_buffer.empty()) {
		//First block is the length
		size_t size = 0;
		size |= (recv_buffer.front());
		recv_buffer.erase(recv_buffer.begin());
		size |= (recv_buffer.front()) << 8;
		recv_buffer.erase(recv_buffer.begin());
		size |= (recv_buffer.front()) << 16;
		recv_buffer.erase(recv_buffer.begin());
		size |= (recv_buffer.front()) << 24;
		recv_buffer.erase(recv_buffer.begin());
		recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + (AES_BLOCK_SIZE - 4));

		//Stop, jack!
		assert(size + bytes_total <= length);

		memcpy(buffer, recv_buffer.data(), size);
		buffer = (char *)buffer + size;

		//How many aes blocks we read = ceil(size/blocksize)
		size_t blocks_read = (size + (AES_BLOCK_SIZE - 1)) / AES_BLOCK_SIZE;
		recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + (blocks_read * AES_BLOCK_SIZE));

		bytes_total += size;
	}

    return bytes_total;
}
