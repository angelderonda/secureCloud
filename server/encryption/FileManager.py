from Encryptor import Encryptor
import os

def ceildiv(a,b):
    return -(a // -b)

class FileManager:
    def write(self, data: bytes, metadata: bytes, filename: str, encryptor: Encryptor):
        # split up data and run recursively if encryptor is an array
        if(isinstance(encryptor, list)):
            seg_length = ceildiv(len(data), len(encryptor))
            for i, enc in enumerate(encryptor):
                self.write(data[seg_length * i: seg_length * (i + 1)],
                           metadata if i == 0 else b'',
                           f"{filename}${i}",
                           enc)
            return
        
        with open(filename,'wb') as f:
            nonce, encrypted, signature = encryptor.encrypt(data, metadata)
            for part in [ metadata, encrypted, nonce, signature]:
                f.write(len(part).to_bytes(4,byteorder='little'))
                f.write(part)

    def read_part(self,file):
        part_len = int.from_bytes(file.read(4), byteorder='little')
        return file.read(part_len)

    def read_metadata_only(self, filename):
        with open(filename, 'rb') as f:
            return self.read_part(f)

    def read_content(self, filename: str, encryptor: Encryptor):
        if(isinstance(encryptor,list)):
            results = []
            for i, enc in enumerate(encryptor):
                results.append(self.read_content(f"{filename}${i}",enc)[1])

            return self.read_metadata_only(f"{filename}$0"),b''.join(results)

        with open(filename, 'rb') as f:
            metadata = self.read_part(f)
            encrypted = self.read_part(f)
            nonce = self.read_part(f)
            signature = self.read_part(f)
            plaintext = encryptor.decrypt(encrypted, metadata, nonce, signature)
        return metadata, plaintext
        
    def secure_erase(self, filename: str, passes = 1):
        with open(filename, 'ab') as f:
            file_len = f.tell()
        with open(filename, 'wb') as f:
            for i in range(passes):
                f.seek(0)
                f.write(os.urandom(file_len))
        os.remove(filename)