from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class Encryptor:
    def __init__(self, key: bytes = None, nonce: bytes = None):
        self.key = key or os.urandom(32)
        self.nonce = nonce or os.urandom(12)
        
        
    def encrypt(self, plaintext: str) -> bytes:
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(self.nonce),
            backend=default_backend()
            
            
        )
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext.encode()) + encryptor.finalize()