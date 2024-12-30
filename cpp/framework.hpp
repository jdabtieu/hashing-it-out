#ifndef FRAMEWORK_HPP
#define FRAMEWORK_HPP

#include <chrono>
#include <string>
#include <vector>
#include <fstream>
#include <cassert>
#include <sys/resource.h>

// Abstract class for benchmarking
class HashBenchmark {
    protected:
        // Generate a cryptographically-secure seed
        void generateSeed(size_t size, char *seed) {
            std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
            urandom.read(seed, size);
            urandom.close();
        }

        // Hexify a byte string into an existing std::string
        // Caller should call hex.reserve(size * 2) before calling this function
        void hexify(unsigned char *bytes, size_t size, std::string &hex) {
            static const char *hexmap = "0123456789abcdef";
            for (size_t i = 0; i < size; i++) {
                hex.push_back(hexmap[bytes[i] >> 4]);
                hex.push_back(hexmap[bytes[i] & 0xf]);
            }
        }

    public:
        std::string name;
        HashBenchmark(std::string name) : name(name) {}

        // Hash a password and return the string representation
        virtual std::string _hash(const std::string &password) = 0;

        // Check if a hash matches a password
        virtual bool _checkHash(const std::string &hash, const std::string &password) = 0;

        // Time taken to compute hashes for every password in the file
        void _computeTime(std::vector<std::string> &passwords) {
            for (const std::string &password : passwords) {
                _hash(password);
            }
        }

        double computeTime(std::string passwordFile) {
            std::vector<std::string> passwords;
            std::ifstream file(passwordFile);
            std::string password;
            while (std::getline(file, password)) {
                passwords.push_back(password);
            }
            file.close();

            auto start = std::chrono::high_resolution_clock::now();
            _computeTime(passwords);
            auto end = std::chrono::high_resolution_clock::now();
            return std::chrono::duration<double>(end - start).count();
        }

        // Time taken to check all the passwords in the file against the hash of the last one
        void _bruteForceTime(std::vector<std::string> &passwords) {
            std::string target = _hash(passwords.back());
            for (const std::string &password : passwords) {
                if (_checkHash(target, password)) {
                    return;
                }
            }
            assert(false);
        }

        double bruteForceTime(std::string passwordFile) {
            std::vector<std::string> passwords;
            std::ifstream file(passwordFile);
            std::string password;
            while (std::getline(file, password)) {
                passwords.push_back(password);
            }
            file.close();

            auto start = std::chrono::high_resolution_clock::now();
            _bruteForceTime(passwords);
            auto end = std::chrono::high_resolution_clock::now();
            return std::chrono::duration<double>(end - start).count();
        }

        // Get stack+heap memory usage of hashing function
        // We can do library memory usage later
        void _memoryFootprintTarget(std::vector<std::string> &passwords) {
            for (const std::string &password : passwords) {
                _hash(password);
            }
        }

        unsigned long long memoryFootprint(std::string passwordFile) {
            std::vector<std::string> passwords;
            std::ifstream file(passwordFile);
            std::string password;
            while (std::getline(file, password)) {
                passwords.push_back(password);
            }
            file.close();

            struct rusage initialMemUsage;
            struct rusage finalMemUsage;
            assert(!getrusage(RUSAGE_SELF, &initialMemUsage));
            _memoryFootprintTarget(passwords);
            assert(!getrusage(RUSAGE_SELF, &finalMemUsage));

            return finalMemUsage.ru_maxrss - initialMemUsage.ru_maxrss;
        }
};

#endif // FRAMEWORK_HPP