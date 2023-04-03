from encryption.Encryptor import Encryptor
from encryption.algorithms import hashes_algorithms, aead_algorithms
import os
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.exceptions import InvalidSignature

class AeadEncryptor(Encryptor):
    def __init__(self, key, algo_name, verbose = False) -> None:
          super().__init__()
          self.algo = aead_algorithms[algo_name](key)
          self.verbose = verbose

    def encrypt(self, data, metadata):
        nonce = os.urandom(12)  # generate a random nonce

        ct = self.algo.encrypt(nonce, data, metadata)  # encrypt the message
        if self.verbose:
            print(f"{ct=}")

        return nonce, ct, b''
    
    def decrypt(self, data, metadata, nonce, signature=None):
        return self.algo.decrypt(nonce, data, metadata)
         