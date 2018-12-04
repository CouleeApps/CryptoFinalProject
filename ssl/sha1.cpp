#include <iostream>
#include <string.h>
#include <math.h>
#include <vector>
#include <gmpxx.h>

#include "common.h"
#include "sha1.h"

#define u8 uint8_t
#define u32 uint32_t
#define u64 uint64_t
using namespace std;

static inline uint32_t rotl32 (uint32_t n, unsigned int c)
{
  const unsigned int mask = (CHAR_BIT*sizeof(n) - 1);  // assumes width is a power of 2.

  // assert ( (c<=mask) &&"rotate by type width or more");
  c &= mask;
  return (n<<c) | (n>>( (-c)&mask ));
}

void sha1_hash(u8 *dst, u8 *message, size_t msg_size){
	u64 pad_size = (u64) ceil((float) msg_size / 64.0) * 64;
	vector<u8> padded;
	
	u32 k = 0;
	u32 h0 = 0x67452301;
	u32 h1 = 0xefcdab89;
	u32 h2 = 0x98badcfe;
	u32 h3 = 0x10325476;
	u32 h4 = 0xc3d2e1f0;
	u32 a, b, c, d, e, f, temp;
	mpz hh;
	for(size_t i = 0; i < msg_size; i++){
		padded.push_back(message[i]);
	}
	padded.push_back(0x80);
	while((padded.size() + k + 8) % 64 != 0){
		k++;
	}
	for(u32 i = 0; i < k; i++){
		padded.push_back(0x0);
	}
	pad_size = msg_size * 8; //reuse pad_size for msg_len in bits
	padded.push_back((u8)(pad_size >> 0x38 & 0xff));
	padded.push_back((u8)(pad_size >> 0x30 & 0xff));
	padded.push_back((u8)(pad_size >> 0x28 & 0xff));
	padded.push_back((u8)(pad_size >> 0x20 & 0xff));
	padded.push_back((u8)(pad_size >> 0x18 & 0xff));
	padded.push_back((u8)(pad_size >> 0x10 & 0xff));
	padded.push_back((u8)(pad_size >> 0x8  & 0xff));
	padded.push_back((u8)(pad_size & 0xff));
	for(int i = 0; i < ceil(((float) msg_size) / 64); i++){
		vector<u32> copy;
		for(int j = i * 64; j < (i + 1) * 64; j+=4){	
			copy.push_back(((((((padded[j] << 0x8) | padded[j+1]) << 0x8 ) | padded[j+2]) << 0x8) | padded[j+3])); 
		}
		for(int j = 16; j < 80; j++){
			copy.push_back(rotl32(copy[j-3] ^ copy[j-8] ^ copy[j-14] ^ copy[j-16], 1));
		}
		a = h0;
		b = h1;
		c = h2;
		d = h3;
		e = h4;
		for(int j = 0; j < 80; j++){
			if(j >= 0 && j <= 19){
				f = (b & c) | ((~b) & d);
				k = 0x5a827999;	
			} else if(j >= 20 && j <= 39){
				f = b ^ c ^ d;
				k = 0x6ed9eba1;
			} else if(j >= 40 && j <= 59){
				f = (b & c) | (b & d) | (c & d);
				k = 0x8f1bbcdc;
			} else if(j >= 60 && j <= 79){
				f = b ^ c ^ d;
				k = 0xca62c1d6;
			}

			temp = rotl32(a, 5) + f + e + k + copy[j];
			e = d;
			d = c;
			c = rotl32(b, 30);
			b = a;
			a = temp;
		}

		h0 = h0 + a;
		h1 = h1 + b;
		h2 = h2 + c;
		h3 = h3 + d;
		h4 = h4 + e;
		copy.clear();
	}

	hh = ((mpz)h0 << 128) | ((mpz)h1 << 96) | ((mpz)h2 << 64) | ((mpz)h3 << 32) | (mpz)h4;
	mpz2array(hh, dst, SHA1_RESULT_SIZE);
}
