#include <crypt.h>
#include <string.h>
#include <errno.h>
#include "framework.hpp"
#include "base64.h"

class Scrypt: public HashBenchmark {
    private:
        int r, p, npow = 0;
        static const int hashLen = 64;
        static const int saltLen = 18;

        std::string _hashInternal(const std::string &password, const char *configStr) {
            char *data = crypt(password.c_str(), configStr);
            assert(errno == 0);
            return std::string(data);
        }
    public:
        Scrypt(std::string name, int n, int r, int p) : HashBenchmark(name), r(r), p(p) {
            while (n > 1) {
                n >>= 1;
                npow++;
            }
        }

        std::string _hash(const std::string &password) {
            uint8_t salt[saltLen];
            generateSeed(saltLen, (char *) salt);
            size_t b64saltLen;
            unsigned char *b64salt = base64_encode(salt, saltLen, &b64saltLen);
            for (int i = b64saltLen; i >= 0; i--) { // Remove padding
                if (b64salt[i] == '=' || b64salt[i] == '\n' || b64salt[i] == '\0') {
                    b64salt[i] = 0;
                } else {
                    break;
                }
            }
            // $7$Nrrrrrppppp$salt$
            char configStr[18 + b64saltLen];
            sprintf(configStr, "$7$%c%c....%c....$%s$", base64_table[npow], base64_table[r], base64_table[p], b64salt);
            free(b64salt);
            return _hashInternal(password, configStr);
        }

        bool _checkHash(const std::string &hash, const std::string &password) {
           return hash == _hashInternal(password, hash.c_str());
        }
};