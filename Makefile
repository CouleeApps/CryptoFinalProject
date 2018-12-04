CXXFLAGS = -std=c++11 -g -Wall -Werror
LXXFLAGS = -lm -lgmp -lgmpxx -lpthread
SSL_DIR = ssl
TESTS_DIR = tests
CHAT_DIR = chat
CHAT_SERVER_DIR = chat/server
CHAT_CLIENT_DIR = chat/client

SSL_DEPS = common.h paillier.h blum_goldwasser.h aes.h rsa.h ssl.h sha1.h hmac.h
SSL_OBJ  = paillier.o blum_goldwasser.o aes.o rsa.o common.o sha1.o ssl.o hmac.o
CHAT_CLIENT_DEPS =
CHAT_CLIENT_OBJ_ =
CHAT_CLIENT_OBJ = $(patsubst %, $(CHAT_CLIENT_DIR)/%, $(CHAT_CLIENT_OBJ_))
CHAT_SERVER_DEPS = handlers.h
CHAT_SERVER_OBJ_ = handlers.o
CHAT_SERVER_OBJ = $(patsubst %, $(CHAT_SERVER_DIR)/%, $(CHAT_SERVER_OBJ_))
DEPS += $(patsubst %, $(SSL_DIR)/%, $(SSL_DEPS))
DEPS += $(patsubst %, $(CHAT_DIR)/%, $(CHAT_DEPS))
OBJ  += $(patsubst %, $(SSL_DIR)/%, $(SSL_OBJ))
TEST_BINS_ = ptest htest_client htest_server bgtest rsatest aestest
TEST_BINS = $(patsubst %, $(TESTS_DIR)/%, $(TEST_BINS_))
CHAT_BINS_ = client/chat_client server/chat_server
CHAT_BINS = $(patsubst %, $(CHAT_DIR)/%, $(CHAT_BINS_))
BINS += $(TEST_BINS) $(CHAT_BINS)

%.o: %.cpp $(DEPS)
	$(CXX) -c -o $@ $< $(CXXFLAGS)

all: tests chat clean

tests: $(TEST_BINS)

tests/ptest: $(OBJ) tests/paillier_test.o
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LXXFLAGS)

tests/htest_client: $(OBJ) tests/handshake_test_client.o
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LXXFLAGS)

tests/htest_server: $(OBJ) tests/handshake_test_server.o
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LXXFLAGS)

tests/bgtest: $(OBJ) tests/bg_test.o
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LXXFLAGS)

tests/rsatest: $(OBJ) tests/rsa_test.o
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LXXFLAGS)

tests/aestest: $(OBJ) tests/aes_test.o
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LXXFLAGS)

chat: $(CHAT_BINS)

chat/server/chat_server: $(OBJ) $(CHAT_SERVER_OBJ) chat/server/main.o
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LXXFLAGS)

chat/client/chat_client: $(OBJ) $(CHAT_CLIENT_OBJ) chat/client/main.o
	$(CXX) -o $@ $^ $(CXXFLAGS) $(LXXFLAGS)

.PHONY: clean
clean:
	rm $(SSL_DIR)/*.o $(TESTS_DIR)/*.o $(CHAT_SERVER_DIR)/*.o $(CHAT_CLIENT_DIR)/*.o

.PHONY: nuke
nuke: clean
	rm $(BINS)
