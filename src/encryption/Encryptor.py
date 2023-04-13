from abc import ABC,abstractmethod

class Encryptor(ABC):
    @abstractmethod
    def encrypt(self, data, metadata):
        raise NotImplementedError()
    
    @abstractmethod
    def decrypt(self, data, metadata, nonce, signature):
        raise NotImplementedError()
    