from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM, AESCCM, AESOCB3, AESSIV

aead_algorithms = {"chacha": ChaCha20Poly1305,
                   "aes-gcm": AESGCM,
                   "aes-ccm": AESCCM,
                   "aes-ocb3": AESOCB3
                   }

from cryptography.hazmat.primitives.ciphers.algorithms import AES256, AES, Camellia

encryption_algorithms = {
    "aes-256": AES256,
    "aes-128": AES,
    "camellia-256": Camellia
}

from cryptography.hazmat.primitives.hashes import SHA256, SHA512, SHA3_256, SHA3_512

hashes_algorithms = {  'sha-256': SHA256,
            'sha-512': SHA512,
            'sha3-256': SHA3_256,
            'sha3-512': SHA3_512}

key_ex_algorithms = ['dh-2048', 'dh-3072', 'dh-4096', 'ecdh-p256', 'ecdh-p384', 'ecdh-p521']

