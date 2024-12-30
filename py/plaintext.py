import framework

class Plaintext(framework.HashBenchmark):
    def __init__(self, name, *args, **kwargs):
        super().__init__(name, *args, **kwargs)
    
    # Hash a password and return the string representation
    def _hash(self, password):
        return password
    
    # Check if a hash matches a password
    def _checkHash(self, hash, password):
        return password == hash