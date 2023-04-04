import requests
from uuid import uuid4
import argparse
import sys
import os, boto3
from encryption.AeadEncryptor import AeadEncryptor
from uuid import uuid4, UUID as TestUUID
import json

# We read de credentials file
with open('credentials.json') as cred_file:
    cred = json.load(cred_file)

# Create the kms client

session = boto3.Session(
    aws_access_key_id=cred['ACCESS_KEY_ID'],
    aws_secret_access_key=cred['SECRET_ACCESS_KEY'],
    region_name=cred['REGION_NAME']
)
kms_client = session.client('kms')

master_key = b'\xee\x9b\xb4F\xda\x16id\xc8\x82\xaf\xed~.\xb5\x19\x7f\r\x85\xd8\xa4\x0e{\xb6\xcf8\xb3M\x8b\xfd\x89z'

master_encryptor = AeadEncryptor(master_key, 'chacha') # To cypher the 



def generate_key():    
    # Generate new key
    response = kms_client.generate_data_key(
        KeyId=cred['KEY_ID'],
        KeySpec='AES_256'
    )  

    return response['Plaintext']

def to_bytes(num):
    return int.to_bytes(num, 4, 'little')


def fromBytes(bytes):
    return int.from_bytes(bytes, 'little')


def upload_cse(filename, metadata, host, output, verify):
    if not os.path.isfile:
        print("Error opening file. Does it exist locally and do you have permissions to open it?")
        sys.exit(1)
    fileid = str(uuid4())
    print(f"Encrypting...")

    dek_key = generate_key()
    dek_encryptor = AeadEncryptor(dek_key,'chacha') # To cypher the files

    with open(filename, mode='rb') as f:
        nonce_dek, encrypted, signature_dek = dek_encryptor.encrypt(
            f.read(), metadata)

    print("Uploading...")

    # Upload includes both unencrypted metadata and encrypted file
    # preceded by their length to restore them afterwards
    to_upload = to_bytes(len(metadata)) + metadata + \
        to_bytes(len(encrypted)) + encrypted
    try:
        requests.post(f'{host}/upload',
                      files={'file': to_upload},
                      data={'dzuuid': fileid,
                            'dzchunkindex': 0,
                            'dztotalchunkcount': 1},
                      verify=verify)
        print(f"Successfully uploaded {filename} with uuid {fileid}!")
    except:
        print("Error uploading encrypted file. If you use self-signed TLS certificates, make sure to pass the -s option.")
        sys.exit(1)

    key_nonce, key_encrypyted, key_signature = master_encryptor.encrypt(dek_key,b'')

    with open(output if output else filename + '.key', 'w+') as f:
        f.write(json.dumps({'nonce_dek': nonce_dek.hex(),
                            'signature_dek': signature_dek.hex(),
                            'nonce_key': key_nonce.hex(),
                            'signature_key': key_signature.hex(),
                            'key': key_encrypyted.hex(),
                            'uuid': fileid}))        
    


def download_cse(keyfile, host, output, verify):
    if not os.path.isfile:
        print("Error opening key file. Does it exist locally and do you have permissions to open it?")
        sys.exit(1)
    with open(keyfile) as f:
        keydata = json.loads(f.read())
    dek_key = master_encryptor.decrypt(bytes.fromhex(keydata["key"]),b'',bytes.fromhex(keydata["nonce_key"]),bytes.fromhex(keydata["signature_key"]))
    dek_encryptor = AeadEncryptor(dek_key,"chacha")

    try:
        result = requests.get(
            f'{host}/download/{keydata["uuid"]}', verify=verify)
        if result.status_code == 404:
            print("Error: the file doesn't exist on the server")
            sys.exit(1)
        if not result.ok:
            raise ConnectionError
    except:
        print("Error downloading encrypted file. If you use self-signed TLS certificates, make sure to pass the -s option.")
        sys.exit(1)

    # to understand this format, look at to_upload in download_cse function above
    metalen = fromBytes(result.content[:4])
    metadata = result.content[4:metalen]
    data = result.content[metalen + 8:]
    plaintext = dek_encryptor.decrypt(
        data, metadata, bytes.fromhex(keydata["nonce_dek"]), bytes.fromhex(keydata["signature_dek"]))

    print(f'Recieved file with metadata: {metadata.decode("utf-8")}')

    # write the encrypted file to output if one was given,
    # or to the location of the keyfile without the .key ending
    with open(output if output else keyfile.split('.key')[0], 'wb') as f:
        f.write(plaintext)

def delete(file, host, verify):
    # test if file is a uuid or a keyfile
    try:
        uuid = str(TestUUID(file, version=4))
    except ValueError:
        try:
            with open(file) as f:
                keydata = json.loads(f.read())
                uuid = keydata["uuid"]
        except:
            print("{file} is neither a valid UUID nor a valid keyfile that could be opened.")
            sys.exit(1)
    

    result = requests.delete(f"{host}/delete/{uuid}", verify=verify)
    if result.status_code == 404:
        print("File does not exist on the server")
        sys.exit(1)
    elif not result.ok:
        print("There was an error deleting the file")
        sys.exit(1)
    
    print("File deleted successfully!")

def main():
    parser = argparse.ArgumentParser("secureCloud client", description='''
The client offers a few different modes that treat the FILE argument differently:

- upload (u): Encrypts a file and uploads it to the server. FILE is the path of said file. Creates a keyfile which is required to decrypt the file later. DO NOT UPLOAD, SHARE OR DELETE THIS FILE!
- donwload (d): Downlads a previously encrypted file from the server and decrypts it. FILE is the path of the keyfile created during upload.
- remove (r, delete): Securely erase a file from the server. FILE can be the keyfile generated by upload, or the file's UUID
    '''
    , formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('MODE', help="What to do.", choices=[
                        "upload", "u", "download", "d", "delete", "remove", "r", "list", "l"])
    parser.add_argument(
        'FILE', help="What file to operate on. Is a local filename in case of upload, file ID otherwise")
    parser.add_argument('--host', default='https://localhost:443',
                        help="Location of the server host. Default https://localhost:443")
    parser.add_argument('-m', '--metadata', default=b'',
                        help="Unencrypted but authenticated data to upload alongside file.")
    parser.add_argument('-s', '--skip-verify', action='store_true', required=False,
                        help='Don\'t verify TLS certificates. Use only for local testing!')
    parser.add_argument('-o', '--output', required=False,
                        help=' When downloading: Location to store file.\nWhen uploading: key file containing nessecary data to decrypt the file later when uploading. Default: <filename>.key')

    args = parser.parse_args()
    print(args.skip_verify)
    if args.MODE == 'u' or args.MODE == 'upload':
        upload_cse(args.FILE, args.metadata, args.host,
                   args.output, not args.skip_verify)
    elif (args.MODE == 'd' or args.MODE == 'download'):
        download_cse(args.FILE, args.host, args.output, not args.skip_verify)
    elif (args.MODE == 'r'):
        delete(args.FILE, args.host, not args.skip_verify)
    else:
        raise NotImplementedError()


if __name__ == '__main__':
    main()
