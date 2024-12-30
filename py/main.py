from argon2_ import Argon2
from pbkdf2 import PBKDF2
from scrypt import Scrypt
from sha256 import Sha256
from plaintext import Plaintext
from framework import HashBenchmark
import subprocess

default_algorithms = [
    ("Argon2", Argon2, {}),
    ("PBKDF2-100k", PBKDF2, {"iters": 100000}),
    ("PBKDF2-600k", PBKDF2, {"iters": 600000}),
    ("PBKDF2-1m", PBKDF2, {"iters": 1000000}),
    ("Scrypt-Mem", Scrypt, {"n": 2**17, "r": 8, "p": 1}),
    ("Scrypt-Balanced", Scrypt, {"n": 2**15, "r": 8, "p": 3}),
    ("Scrypt-CPU", Scrypt, {"n": 2**13, "r": 8, "p": 10}),
    ("SHA-256", Sha256, {}),
    ("Plaintext", Plaintext, {})
]

# [COUNT]x [CPU MODEL], [OS RELEASE], [PYTHON VERSION], [RAM GB]
def get_hardware_string():
    # Get CPU info
    cpu_info = subprocess.run("lscpu", capture_output=True, text=True).stdout.splitlines()
    cpu_count = [x for x in cpu_info if 'CPU(s)' in x][0].split(":")[1].strip()
    cpu_model = [x for x in cpu_info if 'Model name' in x][0].split(":")[1].strip()

    # Get OS info
    os_info = subprocess.run("lsb_release -a", capture_output=True, text=True, shell=True).stdout.splitlines()
    os_release = [x for x in os_info if 'Description' in x][0].split(":")[1].strip()

    # Get Python version
    python_version = subprocess.run("python --version", capture_output=True, text=True, shell=True).stdout.strip()

    # Get RAM amount
    ram_info = subprocess.run("free --giga", capture_output=True, text=True, shell=True).stdout.splitlines()
    ram_gb = [x for x in ram_info if 'Mem' in x][0].split()[1]

    return f"{cpu_count}x {cpu_model},{os_release},{python_version},{ram_gb} GB RAM"

# Computation Time (32 passwords, rockyou32.txt) on all the default algorithms
def computation_time_test1():
    f = open('results/compute1.csv', 'a')
    f.write(f"Computation Time (32 passwords, rockyou32.txt) on all the default algorithms, {get_hardware_string()}\n")
    f.write("Algorithm,Time\n")
    for algorithm in default_algorithms:
        alg: HashBenchmark = algorithm[1](algorithm[0], **algorithm[2])
        elapsed_time = alg.computeTime("../resources/rockyou32.txt")
        print(f"{algorithm[0]}: {elapsed_time} seconds")
        f.write(f"{algorithm[0]},{elapsed_time}\n")
    f.close()

# Computational Time (25k passwords, rockyou25k.txt) on the fast algorithms
def computation_time_test2():
    fast_algorithms = [default_algorithms[-2], default_algorithms[-1]]
    f = open('results/compute2.csv', 'a')
    f.write(f"Computation Time (25k passwords, rockyou25k.txt) on the fast algorithms, {get_hardware_string()}\n")
    f.write("Algorithm,Time\n")
    for algorithm in fast_algorithms:
        alg: HashBenchmark = algorithm[1](algorithm[0], **algorithm[2])
        elapsed_time = alg.computeTime("../resources/rockyou25k.txt")
        print(f"{algorithm[0]}: {elapsed_time} seconds")
        f.write(f"{algorithm[0]},{elapsed_time}\n")
    f.close()

# Memory Use (32 passwords, rockyou32.txt) on all the default algorithms
def memory_use_test1():
    f = open('results/memory1.csv', 'a')
    f.write(f"Memory Use (32 passwords, rockyou32.txt) on all the default algorithms, {get_hardware_string()}\n")
    f.write("Algorithm,Max Usage\n")
    for algorithm in default_algorithms:
        alg: HashBenchmark = algorithm[1](algorithm[0], **algorithm[2])
        max_usage, _ = alg.memoryFootprint("../resources/rockyou32.txt")
        print(f"{algorithm[0]}: Max usage {max_usage} KiB")
        f.write(f"{algorithm[0]},{max_usage * 1024}\n")
    f.close()

# Skip password length test because we already found that passwords with length 4-128 don't really make a dent in compute time
# # Password length test
# outf = open("password_length_test_intel.csv", "w")
# outf.write("Algorithm,Length,Time\n")
# for algorithm in algorithms:
#     alg: HashBenchmark = algorithm[1](algorithm[0], **algorithm[2])
#     for i in range(5):  # Warnup
#         alg._hash("a")
#     for length in range(4, 129, 4):
#         TRIALS_EACH = 5
#         total_time = 0
#         for i in range(TRIALS_EACH):
#             total_time += alg.computeTimeSingle("a" * length)
#         outf.write(f"{algorithm[0]},{length},{total_time / TRIALS_EACH}\n")
#         outf.flush()

def test_argon2_memory_param():
    f = open('results/incr_argon2_mem.csv', 'a')
    f.write(f"Computation Time (32 passwords, rockyou32.txt) on Argon2id with increasing memory cost,{get_hardware_string()}\n")
    f.write("Memcost(B),Time(s),MemoryUsage(KB)\n")
    from argon2 import DEFAULT_MEMORY_COST
    memcost = DEFAULT_MEMORY_COST
    for i in range(5):
        alg = Argon2('Argon2', memcost=memcost)
        elapsed_time = alg.computeTime("../resources/rockyou32.txt")
        memory_usage, _ = alg.memoryFootprint("../resources/rockyou32.txt")
        print(f"{memcost}: {elapsed_time} seconds, {memory_usage} KB")
        f.write(f"{memcost},{elapsed_time},{memory_usage}\n")
        memcost *= 2
    f.close()

def test_argon2_time_param():
    f = open('results/incr_argon2_time.csv', 'a')
    f.write(f"Computation Time (32 passwords, rockyou32.txt) on Argon2id with increasing time cost,{get_hardware_string()}\n")
    f.write("Timecost,Time(s),MemoryUsage(KB)\n")
    for timecost in range(1, 6):  # Default is 3
        alg = Argon2('Argon2', timecost=timecost)
        elapsed_time = alg.computeTime("../resources/rockyou32.txt")
        memory_usage, _ = alg.memoryFootprint("../resources/rockyou32.txt")
        print(f"{timecost}: {elapsed_time} seconds, {memory_usage} KB")
        f.write(f"{timecost},{elapsed_time},{memory_usage}\n")
    f.close()

def test_pbkdf2_iters_param():
    f = open('results/incr_pbkdf2_iters.csv', 'a')
    f.write(f"Computation Time (32 passwords, rockyou32.txt) on PBKDF2 with increasing iterations,{get_hardware_string()}\n")
    f.write("Iters,Time(s),MemoryUsage(KB)\n")
    for iters in [10000, 100000, 200000, 400000, 600000, 1000000, 2000000]:
        alg = PBKDF2('PBKDF2', iters=iters)
        elapsed_time = alg.computeTime("../resources/rockyou32.txt")
        memory_usage, _ = alg.memoryFootprint("../resources/rockyou32.txt")
        print(f"{iters}: {elapsed_time} seconds, {memory_usage} KB")
        f.write(f"{iters},{elapsed_time},{memory_usage}\n")
    f.close()

def test_scrypt_params():
    f = open('results/incr_scrypt.csv', 'a')
    f.write(f"Computation Time (32 passwords, rockyou32.txt) on Scrypt with increasing parameters,{get_hardware_string()}\n")
    f.write("N,R,P,Time(s),MemoryUsage(KB)\n")
    confs = [{"n": 2**17, "r": 8, "p": 1}, {"n": 2**15, "r": 8, "p": 3}, {"n": 2**13, "r": 8, "p": 10}]
    for conf in confs:
        alg = Scrypt('Scrypt', **conf)
        elapsed_time = alg.computeTime("../resources/rockyou32.txt")
        memory_usage, _ = alg.memoryFootprint("../resources/rockyou32.txt")
        print(f"{conf}: {elapsed_time} seconds, {memory_usage} KB")
        f.write(f"{conf['n']},{conf['r']},{conf['p']},{elapsed_time},{memory_usage}\n")
    f.close()

def main():
    memory_use_test1()
    computation_time_test1()
    computation_time_test2()
    test_argon2_memory_param()
    test_argon2_time_param()
    test_pbkdf2_iters_param()
    test_scrypt_params()
    return

if __name__ == "__main__":
    main()
