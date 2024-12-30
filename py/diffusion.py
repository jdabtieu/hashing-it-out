import subprocess
import sys
import random

# 1 - (d-N/2)/(N/2) where d is # of different bits and N is total bits
def diff_idx(s1, s2):
    n = len(s1)
    assert(n == len(s2))

    d = 0
    for i in range(n):
        if s1[i] != s2[i]:
            d += 1
    return 1 - (d - n/2)/(n/2)

def hex_to_bitstring(s):
    return bin(int(s, 16))[2:].zfill(256)

if __name__ == "__main__":
    random.seed(1337)
    random_bitstring = ''.join(random.choices('01', k=256))
    print("Diffusion index")
    print("Alg,Score")
    for alg in ["argon2", "sha256", "pbkdf2-600k", "pbkdf2-1m", "yescrypt", "scrypt-mem", "scrypt-bal", "scrypt-cpu", "plaintext"]:
        total_distance = 0
        trials = 256
        for i in range(trials):
            if i % 32 == 0:
                sys.stderr.write(f"\r{alg}: {i}/{trials}\n")
            # Flip ith bit of random_bitstring
            this_bitstring = random_bitstring[:i] + ('1' if random_bitstring[i] == '0' else '0') + random_bitstring[i+1:]
            hash = subprocess.check_output(["../cpp/hash_one", alg, this_bitstring]).decode().strip()

            distance = diff_idx(this_bitstring, hex_to_bitstring(hash))
            total_distance += distance
        print(alg + "," + str(total_distance / trials))
