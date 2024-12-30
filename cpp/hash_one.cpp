#include "argon2.cpp"
#include "sha256.cpp"
#include "pbkdf2.cpp"
#include "yescrypt.cpp"
#include "scrypt.cpp"
#include "plaintext.cpp"
#include <iostream>

std::string bitstringToString(const std::string &bitstring) {
    std::string res;
    for (int i = 0; i < bitstring.length(); i += 8) {
        char byte = 0;
        for (int j = 0; j < 8; j++) {
            byte <<= 1;
            byte |= bitstring[i + j] - '0';
        }
        res.push_back(byte);
    }
    return res;
}

std::string hexify(unsigned char *bytes, size_t size) {
    std::string hex;
    static const char *hexmap = "0123456789abcdef";
    for (size_t i = 0; i < size; i++) {
        hex.push_back(hexmap[bytes[i] >> 4]);
        hex.push_back(hexmap[bytes[i] & 0xf]);
    }
    return hex;
}

// Hashes a plaintext bitstring using the specified algorithm and prints the resulting hex string
int main(int argc, char **argv) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <algorithm> <plaintext_bitstring>" << std::endl;
        return 1;
    }
    std::string algorithm = argv[1];
    std::string bitstring = argv[2];
    std::string plaintext = bitstringToString(bitstring);
    HashBenchmark *alg;
    if (algorithm == "argon2") alg = new Argon2(algorithm);
    else if (algorithm == "sha256") alg = new Sha256(algorithm);
    else if (algorithm == "pbkdf2-600k") alg = new Pbkdf2(algorithm, 600000);
    else if (algorithm == "pbkdf2-1m") alg = new Pbkdf2(algorithm, 1000000);
    else if (algorithm == "yescrypt") alg = new Yescrypt(algorithm, 4096);
    else if (algorithm == "scrypt-mem") alg = new Scrypt(algorithm, 1 << 17, 8, 1);
    else if (algorithm == "scrypt-bal") alg = new Scrypt(algorithm, 1 << 15, 8, 3);
    else if (algorithm == "scrypt-cpu") alg = new Scrypt(algorithm, 1 << 13, 8, 10);
    else if (algorithm == "plaintext") {
        std::cout << hexify((unsigned char *) plaintext.c_str(), 32) << std::endl;
        return 0;
    } else {
        std::cerr << "Invalid algorithm: " << algorithm << std::endl;
        return 1;
    }
    // Remove salt and other garbage
    std::string hash = alg->_hash(plaintext);
    int hash_part_idx = 0;
    for (int i = 0; i < hash.length(); i++) if (hash[i] == '$') hash_part_idx = i + 1;
    hash = hash.substr(hash_part_idx);

    // Un-base64 scrypt and yescrypt
    if (algorithm == "yescrypt" || algorithm.find("scrypt") != std::string::npos) {
        while (hash.length() % 4 != 0) hash.push_back('=');
        size_t out_len;
        unsigned char *s = base64_decode((const unsigned char *) hash.c_str(), hash.size(), &out_len);
        hash = hexify(s, out_len);
    }
    std::cout << hash << std::endl;
}
