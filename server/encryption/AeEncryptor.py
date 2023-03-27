from Encryptor import Encryptor
from algorithms import hashes_algorithms, encryption_algorithms
import os
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.exceptions import InvalidSignature

class AeEncryptor(Encryptor):
    def __init__(self, key, algo_name, hash_algo_name, verbose = False) -> None:
        self.key = key
        self.algo = encryption_algorithms[algo_name](self.key)
        self.hash_algo = hashes_algorithms[hash_algo_name]()
        self.verbose = verbose

    def encrypt(self, data, metadata):
        iv = os.urandom(16)  # generate a random initialization vector
        encryptor = Cipher(self.algo, modes.CTR(iv)).encryptor()

        # encrypt the message
        ct = encryptor.update(data) + encryptor.finalize()
        if self.verbose:
            print(f"{ct=}")
        hmac = HMAC(self.key, self.hash_algo)  # create a new HMAC instance
        hmac.update(ct)  # update the HMAC with the encrypted message
        signature = hmac.finalize()  # generate the signature
        if self.verbose:
            print(f"{signature=}")

        data = {'enc': 'AE',
                'iv': iv,
                'ct': ct,
                'signature': signature,
                }

        return iv, ct, signature
        
    def decrypt(self, data, metadata, iv, signature):
        # Check signature
        h = HMAC(self.key, algorithm=self.hash_algo)
        h.update(data)
        try:
            h.verify(signature)
        except InvalidSignature:
            print("Recieved encrypted message with invalid signature")
            return

        # Decrypt
        decryptor = Cipher(self.algo, mode=modes.CTR(
            iv)).decryptor()
        plaintext = decryptor.update(data) + decryptor.finalize()
        return plaintext
        