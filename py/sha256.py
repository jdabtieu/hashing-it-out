import hashlib

import framework

class Sha256(framework.HashBenchmark):
    def __init__(self, name, *args, **kwargs):
        super().__init__(name, *args, **kwargs)
    
    # Hash a password and return the string representation
    def _hash(self, password):
        h = hashlib.new('sha256')
        h.update(password.encode('utf-8'))
        return h.hexdigest()
    
    # Check if a hash matches a password
    def _checkHash(self, hash, password):
        return self._hash(password) == hash