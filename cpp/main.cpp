#include "argon2.cpp"
#include "sha256.cpp"
#include "pbkdf2.cpp"
#include "yescrypt.cpp"
#include "scrypt.cpp"
#include "plaintext.cpp"
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <vector>
#include <unistd.h>
#include <unordered_map>
#include <sys/wait.h>

std::vector<HashBenchmark *> default_algorithms;

// yescrypt > 4096 and scrypt > 8192 require hugepages to be allocated
// echo 200 > /proc/sys/vm/nr_hugepages
void initialize(std::vector<HashBenchmark *> &algorithms) {
    algorithms.push_back(new Argon2("Argon2"));
    algorithms.push_back(new Pbkdf2("PBKDF2-100k", 100000));
    algorithms.push_back(new Pbkdf2("PBKDF2-600k", 600000));
    algorithms.push_back(new Pbkdf2("PBKDF2-1m", 1000000));
    algorithms.push_back(new Scrypt("Scrypt-Mem", 1 << 17, 8, 1));
    algorithms.push_back(new Scrypt("Scrypt-Balanced", 1 << 15, 8, 3));
    algorithms.push_back(new Scrypt("Scrypt-CPU", 1 << 13, 8, 10));
    algorithms.push_back(new Yescrypt("yescrypt", 4096));
    algorithms.push_back(new Sha256("sha256"));
    algorithms.push_back(new Plaintext("Plaintext"));
}

// Execute cmd and return stdout
// https://stackoverflow.com/questions/478898/how-do-i-execute-a-command-and-get-the-output-of-the-command-within-c-using-po
std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

// [COUNT]x [CPU MODEL], [OS RELEASE], [PYTHON VERSION], [RAM GB]
std::string get_hardware_string() {
    return exec("python get_hw_string.py");
}

// Computation Time (32 passwords, rockyou32.txt) on all the default algorithms
void computationTimeTest1() {
    std::ofstream f("results/compute1.csv");
    f << "Computation Time (32 passwords, rockyou32.txt) on all the default algorithms, " << get_hardware_string() << std::endl;
    f << "Algorithm,Time" << std::endl;
    for (HashBenchmark *algorithm : default_algorithms) {
        double elapsed_time = algorithm->computeTime("../resources/rockyou32.txt");
        std::cout << algorithm->name << ": " << elapsed_time << " seconds" << std::endl;
        f << algorithm->name << "," << elapsed_time << std::endl;
    }
    f.close();
}

// Computation Time (25k passwords, rockyou25k.txt) on the fast algorithms
void computationTimeTest2() {
    size_t alg_len = default_algorithms.size();
    std::vector<HashBenchmark *> fast_algorithms = {default_algorithms[alg_len - 2], default_algorithms[alg_len - 1]};
    std::ofstream f("results/compute2.csv");
    f << "Computation Time (25k passwords, rockyou25k.txt) on the fast algorithms, " << get_hardware_string() << std::endl;
    f << "Algorithm,Time" << std::endl;
    for (HashBenchmark *algorithm : fast_algorithms) {
        double elapsed_time = algorithm->computeTime("../resources/rockyou25k.txt");
        std::cout << algorithm->name << ": " << elapsed_time << " seconds" << std::endl;
        f << algorithm->name << "," << elapsed_time << std::endl;
    }
    f.close();
}

// Memory Use (32 passwords, rockyou32.txt) on all the default algorithms
// fork is required for memory benchmarking to keep maxrss stats independent
// hugepage_scout.py is used to check hugepage usage as it is not reported via getrusage(2)
// Specifically required for yescrypt > 4096 and scrypt > 8192
void memoryUseTest1() {
    std::ofstream f("results/memory1.csv");
    f << "Memory Use (32 passwords, rockyou32.txt) on all the default algorithms, " << get_hardware_string() << std::endl;
    f << "Algorithm,Max Usage" << std::endl;
    f.close();
    for (HashBenchmark *algorithm : default_algorithms) {
        pid_t pid = fork();
        if (pid == 0) {
            std::ofstream f1("results/memory1.csv", std::ios_base::app);
            int max_usage = algorithm->memoryFootprint("../resources/rockyou32.txt");
            std::cout << algorithm->name << ": Max usage " << max_usage << " KiB" << std::endl;
            f1 << algorithm->name << "," << max_usage * 1024 << std::endl;
            f1.close();
            _exit(0);
        } else {
            pid_t pid2 = fork();
            if (pid2 == 0) {
                const char *const args[3] = {"python", "hugepage_scout.py", NULL};
                execvp("python", const_cast<char *const *>(args));
                assert(false);
            }
            waitpid(pid, NULL, 0);
            kill(pid2, SIGINT);
        }
    }
}

// Memory Use (32 passwords, rockyou32.txt) on Argon2id with increasing memory cost
void test_argon2_memory_param() {
    std::ofstream f("results/incr_argon2_mem.csv");
    f << "Computation Time (32 passwords, rockyou32.txt) on Argon2id with increasing memory cost, " << get_hardware_string() << std::endl;
    f << "Memcost(B),Time(s),MemoryUsage(KB)" << std::endl;
    f.close();
    int memcost = 65536;
    for (int i = 0; i < 5; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            std::ofstream f1("results/incr_argon2_mem.csv", std::ios_base::app);
            Argon2 alg("Argon2", 3, memcost);
            int memory_usage = alg.memoryFootprint("../resources/rockyou32.txt");
            double elapsed_time = alg.computeTime("../resources/rockyou32.txt");
            std::cout << memcost << ": " << elapsed_time << " seconds, " << memory_usage << " KB" << std::endl;
            f1 << memcost << "," << elapsed_time << "," << memory_usage << std::endl;
            f1.close();
            _exit(0);
        } else {
            waitpid(pid, NULL, 0);
        }
        memcost *= 2;
    }
}

// Computation Time (32 passwords, rockyou32.txt) on Argon2id with increasing time cost
void test_argon2_time_param() {
    std::ofstream f("results/incr_argon2_time.csv");
    f << "Computation Time (32 passwords, rockyou32.txt) on Argon2id with increasing time cost, " << get_hardware_string() << std::endl;
    f << "Timecost,Time(s),MemoryUsage(KB)" << std::endl;
    f.close();
    for (int timecost = 1; timecost < 6; timecost++) {
        pid_t pid = fork();
        if (pid == 0) {
            std::ofstream f1("results/incr_argon2_time.csv", std::ios_base::app);
            Argon2 alg("Argon2", timecost, 65536);
            int memory_usage = alg.memoryFootprint("../resources/rockyou32.txt");
            double elapsed_time = alg.computeTime("../resources/rockyou32.txt");
            std::cout << timecost << ": " << elapsed_time << " seconds, " << memory_usage << " KB" << std::endl;
            f1 << timecost << "," << elapsed_time << "," << memory_usage << std::endl;
            f1.close();
            _exit(0);
        } else {
            waitpid(pid, NULL, 0);
        }
    }
}

// Computation Time (32 passwords, rockyou32.txt) on PBKDF2 with increasing iterations
void test_pbkdf2_iters_param() {
    std::ofstream f("results/incr_pbkdf2_iters.csv");
    f << "Computation Time (32 passwords, rockyou32.txt) on PBKDF2 with increasing iterations, " << get_hardware_string() << std::endl;
    f << "Iters,Time(s),MemoryUsage(KB)" << std::endl;
    f.close();
    for (int iters : {10000, 100000, 200000, 400000, 600000, 1000000, 2000000}) {
        pid_t pid = fork();
        if (pid == 0) {
            std::ofstream f1("results/incr_pbkdf2_iters.csv", std::ios_base::app);
            Pbkdf2 alg("PBKDF2", iters);
            int memory_usage = alg.memoryFootprint("../resources/rockyou32.txt");
            double elapsed_time = alg.computeTime("../resources/rockyou32.txt");
            std::cout << iters << ": " << elapsed_time << " seconds, " << memory_usage << " KB" << std::endl;
            f1 << iters << "," << elapsed_time << "," << memory_usage << std::endl;
            f1.close();
            _exit(0);
        } else {
            waitpid(pid, NULL, 0);
        }
    }
}

// Computation Time (32 passwords, rockyou32.txt) on Scrypt with increasing parameters
void test_scrypt_params() {
    std::ofstream f("results/incr_scrypt.csv");
    f << "Computation Time (32 passwords, rockyou32.txt) on Scrypt with increasing parameters, " << get_hardware_string() << std::endl;
    f << "N,R,P,Time(s),MemoryUsage(KB)" << std::endl;
    f.close();
    std::vector<std::unordered_map<std::string, int>> confs = {
        {{"n", 1 << 17}, {"r", 8}, {"p", 1}},
        {{"n", 1 << 15}, {"r", 8}, {"p", 1}},
        {{"n", 1 << 13}, {"r", 8}, {"p", 1}}
    };
    for (auto conf : confs) {
        pid_t pid = fork();
        if (pid == 0) {
            std::ofstream f1("results/incr_scrypt.csv", std::ios_base::app);
            Scrypt alg("Scrypt", conf["n"], conf["r"], conf["p"]);
            int memory_usage = alg.memoryFootprint("../resources/rockyou32.txt");
            double elapsed_time = alg.computeTime("../resources/rockyou32.txt");
            std::cout << conf["n"] << ": " << elapsed_time << " seconds, " << memory_usage << " KB" << std::endl;
            f1 << conf["n"] << "," << conf["r"] << "," << conf["p"] << "," << elapsed_time << "," << memory_usage << std::endl;
            f1.close();
            _exit(0);
        } else {
            pid_t pid2 = fork();
            if (pid2 == 0) {
                const char *const args[3] = {"python", "hugepage_scout.py", NULL};
                execvp("python", const_cast<char *const *>(args));
                assert(false);
            }
            waitpid(pid, NULL, 0);
            kill(pid2, SIGINT);
        }
    }
}

// Computation Time (32 passwords, rockyou32.txt) on Yescrypt with increasing parameters
void test_yescrypt_params() {
    std::ofstream f("results/incr_yescrypt.csv");
    f << "Computation Time (32 passwords, rockyou32.txt) on Yescrypt with increasing parameters, " << get_hardware_string() << std::endl;
    f << "N,Time(s),MemoryUsage(KB)" << std::endl;
    f.close();
    for (int n : {4096, 8192, 16384, 32768, 65536}) {
        pid_t pid = fork();
        if (pid == 0) {
            std::ofstream f1("results/incr_yescrypt.csv", std::ios_base::app);
            Yescrypt alg("yescrypt", n);
            int memory_usage = alg.memoryFootprint("../resources/rockyou32.txt");
            double elapsed_time = alg.computeTime("../resources/rockyou32.txt");
            std::cout << n << ": " << elapsed_time << " seconds, " << memory_usage << " KB" << std::endl;
            f1 << n << "," << elapsed_time << "," << memory_usage << std::endl;
            f1.close();
            _exit(0);
        } else {
            pid_t pid2 = fork();
            if (pid2 == 0) {
                const char *const args[3] = {"python", "hugepage_scout.py", NULL};
                execvp("python", const_cast<char *const *>(args));
                assert(false);
            }
            waitpid(pid, NULL, 0);
            kill(pid2, SIGINT);
        }
    }
}

int main() {
    initialize(default_algorithms);
    
    // Default configuration memory test
    memoryUseTest1();

    // // Paramter-based time and memory tests
    test_argon2_memory_param();
    test_argon2_time_param();
    test_pbkdf2_iters_param();
    test_scrypt_params();
    test_yescrypt_params();

    // // Computation time only tests
    // // Must be run after all other tests or on their own
    computationTimeTest1();
    computationTimeTest2();
    return 0;
}