#ifndef __AES_H_
#define __AES_H_

#include <vector>
#include <stdint.h>

#define AES_KEY_LENGTH 16
#define AES_BLOCK_SIZE 16

std::vector<uint8_t> aes_encrypt(uint8_t cipher[AES_BLOCK_SIZE], uint8_t key[AES_KEY_LENGTH]);
std::vector<uint8_t> aes_decrypt(uint8_t message[AES_BLOCK_SIZE], uint8_t key[AES_KEY_LENGTH]);

#endif
