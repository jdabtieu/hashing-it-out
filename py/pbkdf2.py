import hashlib
import os

import framework

class PBKDF2(framework.HashBenchmark):
    def __init__(self, name, *args, **kwargs):
        super().__init__(name, *args, **kwargs)
        if 'iters' not in kwargs:
            raise ValueError("Missing iters argument")
        self.iters = kwargs['iters']
    
    # Hash a password and return the string representation
    def _hash(self, password):
        salt = os.urandom(16)
        return salt.hex() + ":" + hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, self.iters).hex()
    
    # Check if a hash matches a password
    def _checkHash(self, hash, password):
        salt, hash = hash.split(':')
        salt = int(salt, 16).to_bytes(16, byteorder='big')
        return hash == hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, self.iters).hex()