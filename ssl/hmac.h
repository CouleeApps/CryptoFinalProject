#include "common.h"
#include "sha1.h"

#define HASH_FN sha1_hash
#define BLOCK_SIZE 16
#define HASH_SIZE SHA1_RESULT_SIZE

std::vector<uint8_t> hmac(const std::vector<uint8_t> &K, const std::vector<uint8_t> &m);
