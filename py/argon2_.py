from argon2 import PasswordHasher, DEFAULT_MEMORY_COST, DEFAULT_TIME_COST
from argon2.exceptions import VerifyMismatchError
import base64

import framework

class Argon2(framework.HashBenchmark):
    def __init__(self, name, *args, **kwargs):
        super().__init__(name, *args, **kwargs)
        self.memcost = kwargs.get("memcost", DEFAULT_MEMORY_COST)
        self.timecost = kwargs.get("timecost", DEFAULT_TIME_COST)
    
    # Hash a password and return the string representation
    # To be implemented by subclasses
    def _hash(self, password):
        ph = PasswordHasher(time_cost=self.timecost, memory_cost=self.memcost)
        return ph.hash(password)
    
    # Hash a password and return the integer representation
    # To be implemented by subclasses
    def _hashInt(self, password):
        hashPart = self._hash(password).split('$')[-1]
        return int.from_bytes(base64.b64decode(hashPart + '=='), byteorder='big')
    
    # Check if a hash matches a password
    # To be implemented by subclasses
    def _checkHash(self, hash, password):
        ph = PasswordHasher(time_cost=self.timecost, memory_cost=self.memcost)
        try:
            return ph.verify(hash, password)
        except VerifyMismatchError:
            return False