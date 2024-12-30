import subprocess
import sys
import random

def damerau_levenshtein_distance(s1, s2):
    len_s1 = len(s1)
    len_s2 = len(s2)

    # Create a matrix (distance matrix) with dimensions (len_s1+1) x (len_s2+1)
    # d[i][j] represents the edit distance between s1[:i] and s2[:j].
    d = [[0] * (len_s2 + 1) for i in range(len_s1 + 1)]

    # Initialize the first row and column
    for i in range(len_s1 + 1):
        d[i][0] = i
    for j in range(len_s2 + 1):
        d[0][j] = j

    # Compute the distance
    for i in range(1, len_s1 + 1):
        for j in range(1, len_s2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1

            # Consider substitution, insertion, deletion
            d[i][j] = min(
                d[i - 1][j] + 1,    # Deletion
                d[i][j - 1] + 1,    # Insertion
                d[i - 1][j - 1] + cost  # Substitution (or match if cost=0)
            )

            # Check for transposition
            if i > 1 and j > 1 and s1[i - 1] == s2[j - 2] and s1[i - 2] == s2[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)

    return d[len_s1][len_s2]

def hex_to_bitstring(s):
    return bin(int(s, 16))[2:].zfill(256)

if __name__ == "__main__":
    random.seed(1337)
    random_bitstring = ''.join(random.choices('01', k=256))
    print("D-L distance")
    print("Alg,D-L Ratio")
    for alg in ["argon2", "sha256", "pbkdf2-600k", "pbkdf2-1m", "yescrypt", "scrypt-mem", "scrypt-bal", "scrypt-cpu", "plaintext"]:
        total_distance = 0
        trials = 256
        for i in range(trials):
            if i % 32 == 0:
                sys.stderr.write(f"\r{alg}: {i}/{trials}\n")
            # Flip ith bit of random_bitstring
            this_bitstring = random_bitstring[:i] + ('1' if random_bitstring[i] == '0' else '0') + random_bitstring[i+1:]
            hash = subprocess.check_output(["../cpp/hash_one", alg, this_bitstring]).decode().strip()

            distance = damerau_levenshtein_distance(this_bitstring, hex_to_bitstring(hash))
            total_distance += distance
        print(alg + "," + str(total_distance / trials / 256))  # length of 256, 256 trials

