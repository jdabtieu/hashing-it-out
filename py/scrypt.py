import hashlib
import os

import framework

class Scrypt(framework.HashBenchmark):
    def __init__(self, name, *args, **kwargs):
        """
        Acceptable values for (n, r, p) are
        N=2^17 (128 MiB), r=8 (1024 bytes), p=1
        N=2^16 (64 MiB), r=8 (1024 bytes), p=2
        N=2^15 (32 MiB), r=8 (1024 bytes), p=3
        N=2^14 (16 MiB), r=8 (1024 bytes), p=5
        N=2^13 (8 MiB), r=8 (1024 bytes), p=10
        """
        super().__init__(name, *args, **kwargs)
        if 'n' not in kwargs or 'r' not in kwargs or 'p' not in kwargs:
            raise ValueError("Scrypt requires n, r, and p parameters")
        self.n = kwargs['n']
        self.r = kwargs['r']
        self.p = kwargs['p']
    
    # Hash a password and return the string representation
    def _hash(self, password):
        salt = os.urandom(16)
        return salt.hex() + ":" + hashlib.scrypt(password.encode('utf-8'), salt=salt, n=self.n, r=self.r, p=self.p, maxmem=2147483646).hex()
    
    # Check if a hash matches a password
    def _checkHash(self, hash, password):
        salt, hash = hash.split(':')
        salt = int(salt, 16).to_bytes(16, byteorder='big')
        return hash == hashlib.scrypt(password.encode('utf-8'), salt=salt, n=self.n, r=self.r, p=self.p, maxmem=2147483646).hex()
