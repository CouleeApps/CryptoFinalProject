#ifndef __SHA1_H_
#define __SHA1_H_

#include <stdint.h>
#include <stdlib.h>

#define SHA1_RESULT_SIZE 20

void sha1_hash(uint8_t *dst, uint8_t *message, size_t len);

#endif
