#include "framework.hpp"

class Plaintext: public HashBenchmark {
    public:
        Plaintext(std::string name) : HashBenchmark(name) {}

        std::string _hash(const std::string &password) {
            return password;
        }

        bool _checkHash(const std::string &hash, const std::string &password) {
            return password == hash;
        }
};