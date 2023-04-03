import requests
from uuid import uuid4
import argparse
import sys
import os
from encryption.AeadEncryptor import AeadEncryptor
from uuid import uuid4
import json

master_key = b'\xee\x9b\xb4F\xda\x16id\xc8\x82\xaf\xed~.\xb5\x19\x7f\r\x85\xd8\xa4\x0e{\xb6\xcf8\xb3M\x8b\xfd\x89z'

master_encryptor = AeadEncryptor(master_key, 'chacha')


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

    with open(filename, mode='rb') as f:
        nonce, encrypted, signature = master_encryptor.encrypt(
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
        print(f"Successfully uploaded {filename}!")
    except:
        print("Error uploading encrypted file. If you use self-signed TLS certificates, make sure to pass the -s option.")
        sys.exit(1)

    with open(output if output else filename + '.key', 'w+') as f:
        f.write(json.dumps({'type': 'master', 'nonce': nonce.hex(),
                'signature': signature.hex(), 'uuid': fileid}))


def download_cse(keyfile, host, output, verify):
    if not os.path.isfile:
        print("Error opening key file. Does it exist locally and do you have permissions to open it?")
        sys.exit(1)
    with open(keyfile) as f:
        keydata = json.loads(f.read())
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
    plaintext = master_encryptor.decrypt(
        data, metadata, bytes.fromhex(keydata["nonce"]), bytes.fromhex(keydata["signature"]))

    print(f'Recieved file with metadata: {metadata.decode("utf-8")}')

    # write the encrypted file to output if one was given,
    # or to the location of the keyfile without the .key ending
    with open(output if output else keyfile.split('.key')[0], 'wb') as f:
        f.write(plaintext)


def main():
    parser = argparse.ArgumentParser("secureCloud client")
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
    else:
        raise NotImplementedError()


if __name__ == '__main__':
    main()
