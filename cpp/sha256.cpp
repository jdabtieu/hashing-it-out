#include <openssl/sha.h>
#include "framework.hpp"

class Sha256: public HashBenchmark {
    private:
        static const int hashLen = 32;
        inline void _hashInternal(const std::string &password, unsigned char *hash) {
            SHA256(reinterpret_cast<const unsigned char*>(password.data()), password.size(), hash);
        }
    public:
        Sha256(std::string name) : HashBenchmark(name) {}

        std::string _hash(const std::string &password) {
            unsigned char hash[hashLen];
            _hashInternal(password, hash);
            std::string res;
            res.reserve(hashLen * 2);
            hexify(hash, hashLen, res);
            return res;
        }

        bool _checkHash(const std::string &hash, const std::string &password) {
            return hash == _hash(password);
        }
};