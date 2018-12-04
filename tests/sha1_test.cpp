#include <string>
#include "../ssl/sha1.h"

//'abc' = a9993e364706816aba3e25717850c26c9cd0d89d
int main(int argc, char** argv){
	std::string str = "abc";
	uint8_t lol[str.size()];
	for(int i = 0; i < str.size(); i++){
		lol[i] = (uint8_t)str[i];
	}

	uint8_t hash[SHA1_RESULT_SIZE];
	sha1_hash(hash, lol, str.size());

	printf("Hash is: ");
	for (int i = SHA1_RESULT_SIZE - 1; i >= 0; i --) {
		printf("%02hhx", hash[i]);
	}
	printf("\n");
}
