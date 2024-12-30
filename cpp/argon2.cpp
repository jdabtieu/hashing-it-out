#include <argon2.h>
#include <string.h>
#include "framework.hpp"

class Argon2: public HashBenchmark {
    private:
        unsigned int timecost;
        unsigned int memcost;
        static const int hashLen = 32;
        static const int saltLen = 16;
        // Hashes the password and stores the result in the hash array
        void _hashInternal(const std::string &password, uint8_t *hash, uint8_t *salt) {
            argon2_context ctx = {
                hash, hashLen,   // Output
                (uint8_t *) password.c_str(), (uint32_t) password.length(),  // Password
                salt, saltLen,   // Salt
                NULL, 0,    // Secret data
                NULL, 0,    // Associated Data
                timecost, memcost, 4, 4, // Parameters (t=3, m=65536, p=4, version=19)
                0x13,
                NULL,
                NULL,
                0,
            };
            assert(argon2_ctx(&ctx, Argon2_id) == ARGON2_OK);
        }
    public:
        Argon2(std::string name) : HashBenchmark(name) {
            timecost = 3;
            memcost = 65536;
        }

        Argon2(std::string name, unsigned int timecost, unsigned int memcost) : HashBenchmark(name), timecost(timecost), memcost(memcost) {}

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