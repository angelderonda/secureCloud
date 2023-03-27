from AeEncryptor import AeEncryptor
from AeadEncryptor import AeadEncryptor
import os
from FileManager import FileManager

key = os.urandom(32)
enc_ae = AeEncryptor(key,'aes-256','sha-256')
enc_aead = AeadEncryptor(key,'chacha')

data = b'a message'
metadata = b'some other stuff'

result_ae = enc_ae.encrypt(data,metadata)
result_aead = enc_aead.encrypt(data,metadata)
print(result_ae, result_aead)

dec_ae = enc_ae.decrypt(result_ae[1],metadata, result_ae[0], result_ae[2])
dec_aead = enc_aead.decrypt(result_aead[1],metadata, result_aead[0], result_aead[2])
print(dec_ae)
print(dec_aead)

# Write to a file with split data

fm = FileManager()

fm.write(data, metadata,'a.txt',[enc_ae, enc_aead])

print(fm.read_metadata_only('a.txt$0'))
print(fm.read_content('a.txt$0', enc_ae))
print(fm.read_content('a.txt', [enc_ae,enc_aead]))

fm.secure_erase('a.txt$0')
fm.secure_erase('a.txt$1',10)