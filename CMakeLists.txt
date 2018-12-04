cmake_minimum_required(VERSION 3.0)
project(CryptoProj CXX)

set(CMAKE_CXX_STANDARD 14)

add_library(ssl ssl/common.cpp ssl/ssl.cpp ssl/rsa.cpp ssl/aes.cpp ssl/paillier.cpp ssl/blum_goldwasser.cpp ssl/hmac.cpp ssl/sha1.cpp)

add_executable(rsa_test tests/rsa_test.cpp)
add_executable(bg_test tests/bg_test.cpp)
add_executable(paillier_test tests/paillier_test.cpp)
add_executable(sha1_test tests/sha1_test.cpp)
add_executable(handshake_test_server tests/handshake_test_server.cpp)
add_executable(handshake_test_client tests/handshake_test_client.cpp)

target_link_libraries(ssl gmp gmpxx)

target_link_libraries(rsa_test ssl gmp gmpxx)
target_link_libraries(bg_test ssl gmp gmpxx)
target_link_libraries(paillier_test ssl gmp gmpxx)
target_link_libraries(sha1_test ssl gmp gmpxx)
target_link_libraries(handshake_test_server ssl gmp gmpxx)
target_link_libraries(handshake_test_client ssl gmp gmpxx)

add_executable(crypto_chat_server chat/server/main.cpp chat/server/handlers.cpp)
add_executable(crypto_chat_client chat/client/main.cpp)
target_link_libraries(crypto_chat_server ssl)
target_link_libraries(crypto_chat_client ssl)
