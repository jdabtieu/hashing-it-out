from time import process_time, perf_counter, sleep
from memory_profiler import memory_usage

# Abstract class for benchmarking
class HashBenchmark:
    def __init__(self, name, *args, **kwargs):
        self.name = name
    
    # Hash a password and return the string representation
    # To be implemented by subclasses
    def _hash(self, password):
        raise NotImplementedError()
    
    # Check if a hash matches a password
    # To be implemented by subclasses
    def _checkHash(self, hash, password):
        raise NotImplementedError()
    
    # Time taken to compute hashes for every password in the file
    def _computeTime(self, passwords):
        for password in passwords:
            self._hash(password)
    
    def computeTime(self, passwordFile):
        with open(passwordFile, 'r') as file:
            passwords = file.readlines()
            passwords = [x.strip() for x in passwords]
            if passwords[-1] == "":
                passwords = passwords[:-1]
        start = process_time()
        self._computeTime(passwords)
        return process_time() - start

    def computeTimeSingle(self, password):
        start = process_time()
        self._hash(password)
        return process_time() - start

    
    # Time taken to check all the passwords in the file against the hash of the last one
    def _bruteForceTime(self, passwords):
        target = self._hash(passwords[-1])
        for password in passwords:
            if self._checkHash(target, password):
                return password
        assert(False)
    
    def bruteForceTime(self, passwordFile):
        with open(passwordFile, 'r') as file:
            passwords = file.readlines()
            passwords = [x.strip() for x in passwords]
            if passwords[-1] == "":
                passwords = passwords[:-1]
        start = process_time()
        self._bruteForceTime(passwords)
        return process_time() - start
    
    # Get stack+heap memory usage of hashing function
    # We don't care about library memory usage because Python is fat anyways
    def _memoryFootprint(self, passwords):
        sleep(0.1)  # Get initial memory reading
        for password in passwords:
            self._hash(password)
        sleep(0.1)  # Get final memory reading
    
    def memoryFootprint(self, passwordFile):
        with open(passwordFile, 'r') as file:
            passwords = file.readlines()
            passwords = [x.strip() for x in passwords]
        mem_usage = memory_usage((self._memoryFootprint, (passwords,)), interval=0.05)
        return max(mem_usage) - min(mem_usage), mem_usage[-1] - min(mem_usage)