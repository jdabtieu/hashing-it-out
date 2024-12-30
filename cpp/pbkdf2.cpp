#include <openssl/evp.h>
#include <string.h>
#include "framework.hpp"

class Pbkdf2: public HashBenchmark {
    private:
        int iters;
        static const int hashLen = 32;
        static const int saltLen = 16;
        void _hashInternal(const std::string &password, unsigned char *hash, unsigned char *salt) {
            PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, 16, iters, EVP_sha256(), hashLen, hash);
        }
    public:
        Pbkdf2(std::string name, int iters) : HashBenchmark(name), iters(iters) {}

        std::string _hash(const std::string &password) {
            uint8_t hash[hashLen];
            uint8_t salt[saltLen];
            generateSeed(saltLen, (char *) salt);
            _hashInternal(password, hash, salt);
            std::string resStr;
            resStr.reserve(2 * hashLen + 2 * saltLen + 1);
            hexify(salt, saltLen, resStr);
            resStr.push_back('$');
            hexify(hash, hashLen, resStr);
            return resStr;
        }

        bool _checkHash(const std::string &hash, const std::string &password) {
            if (hash.length() != 2 * hashLen + 2 * saltLen + 1 || hash[2 * saltLen] != '$') {
                return false;
            }
            uint8_t hsh[hashLen];
            uint8_t salt[saltLen];
            for (int i = 0; i < saltLen; i++) {
                char byte[3] = {hash[2 * i], hash[2 * i + 1], 0};
                salt[i] = (uint8_t) strtol(byte, NULL, 16);
            }
            _hashInternal(password, hsh, salt);
            std::string resStr;
            resStr.reserve(2 * hashLen);
            hexify(hsh, hashLen, resStr);
            return memcmp(resStr.data(), hash.data() + 2 * saltLen + 1, 2 * hashLen) == 0;
        }
};