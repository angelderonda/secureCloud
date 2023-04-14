import requests
from uuid import uuid4
import argparse
import sys
import re
import os
import boto3
from encryption.AeadEncryptor import AeadEncryptor
from getpass import getpass
from encryption.AeEncryptor import AeEncryptor
from encryption.algorithms import aead_algorithms, encryption_algorithms
from uuid import uuid4, UUID as TestUUID
import json
import urllib3
import bcrypt
import pickle
import datetime

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# We read de credentials file
with open("credentials.json") as cred_file:
    cred = json.load(cred_file)

# Create the kms client
session = boto3.Session(
    aws_access_key_id=cred["ACCESS_KEY_ID"],
    aws_secret_access_key=cred["SECRET_ACCESS_KEY"],
    region_name=cred["REGION_NAME"],
)
kms_client = session.client("kms")


def create_or_reuse_master_key():
    # Define the directory containing the key files
    key_dir = "keys/"

    # Find the file with the highest numeric suffix
    key_pattern = re.compile(r"key(\d+)\.json")
    key_nums = [
        int(key_pattern.match(fname).group(1))
        for fname in os.listdir(key_dir)
        if key_pattern.match(fname)
    ]
    max_key_num = max(key_nums) if key_nums else 0
    max_key_file = os.path.join(key_dir, f"key{max_key_num:03d}.json")

    # Load the contents of the file
    with open(max_key_file, "r") as f:
        master_key_data = json.load(f)

    # Check the remaining uses field to determine whether to create a new key or use the existing one
    if master_key_data["remaining_uses"] == 0:
        # Create a new key and write it to a new file
        new_key_id = str(max_key_num + 1).zfill(3)
        new_key_file = os.path.join(key_dir, f"key{new_key_id}.json")
        master_key = os.urandom(32)
        # Generate the new key here...
        new_key_data = {
            "key_id": new_key_id,
            "master_key": list(
                master_key
            ),  # Convert binary data to a list for JSON serialization
            "remaining_uses": 99,
        }
        with open(new_key_file, "w") as f:
            json.dump(new_key_data, f)
        return master_key, new_key_id
    else:
        # Use the existing key
        master_key = bytes(master_key_data["master_key"])
        # Decrement the remaining uses field
        master_key_data["remaining_uses"] -= 1
        with open(max_key_file, "w") as f:
            json.dump(master_key_data, f)
        return master_key, master_key_data["key_id"]


def search_master_key(id):
    key_file = os.path.join("keys/", f"key{id}.json")
    # Load the contents of the file
    with open(key_file, "r") as f:
        master_key_data = json.load(f)
    master_key = bytes(master_key_data["master_key"])
    return master_key


def generate_key():
    # Generate new key
    response = kms_client.generate_data_key(
        KeyId=cred["KEY_ID"], KeySpec="AES_256")
    return response["Plaintext"]


def to_bytes(num):
    return int.to_bytes(num, 4, "little")  # little endian


def fromBytes(bytes):
    return int.from_bytes(bytes, "little")  # little endian


def get_encryptor(key, algo_name, hash_algo_name="sha-256"):
    if algo_name in encryption_algorithms:
        return AeEncryptor(key, algo_name, hash_algo_name)
    if algo_name in aead_algorithms:
        return AeadEncryptor(key, algo_name)
    raise ValueError(f"Unknown encryption algorithm name: {algo_name}")


def upload_cse(filename, metadata, host, output, verify, enc_algo):
    if not os.path.isfile(filename):
        print(
            "Error opening file. Does it exist locally and do you have permissions to open it?"
        )
        sys.exit(1)
    fileid = str(uuid4())
    print(f"Encrypting...")

    dek_key = generate_key()
    dek_encryptor = get_encryptor(dek_key, enc_algo)  # To cypher the files

    with open(filename, mode="rb") as f:
        nonce_dek, encrypted, signature_dek = dek_encryptor.encrypt(
            f.read(), metadata)

    print("Uploading...")

    # Upload includes both unencrypted metadata and encrypted file
    # preceded by their length to restore them afterwards
    to_upload = (
        to_bytes(len(metadata)) + metadata +
        to_bytes(len(encrypted)) + encrypted
    )
    try:
        requests.post(
            f"{host}/upload",
            files={"file": to_upload},
            data={
                "dzuuid": fileid,
                "dzchunkindex": 0,
                "dztotalchunkcount": 1,
                "filename": filename,
            },
            verify=verify,
        )
        print(f"Successfully uploaded {filename} with uuid {fileid}!")
    except:
        print(
            "Error uploading encrypted file. If you use self-signed TLS certificates, make sure to pass the -s option."
        )
        sys.exit(1)

    master_key, key_id = create_or_reuse_master_key()
    master_encryptor = get_encryptor(master_key, "chacha")
    key_nonce, key_encrypyted, key_signature = master_encryptor.encrypt(
        dek_key, b"")
    password = getpass("Enter password to protect the key file: ")
    password2 = getpass("Enter password again: ")
    while password != password2:
        print("Passwords do not match. Try again.")
        password = getpass("Enter password to protect the key file: ")
        password2 = getpass("Enter password again: ")
    password = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password, salt)

    with open(output if output else filename + ".key", "w+") as f:
        f.write(
            json.dumps(
                {
                    "nonce_dek": nonce_dek.hex(),
                    "signature_dek": signature_dek.hex(),
                    "nonce_key": key_nonce.hex(),
                    "signature_key": key_signature.hex(),
                    "key": key_encrypyted.hex(),
                    "key_id": key_id,
                    "uuid": fileid,
                    "enc_algo": enc_algo,
                    "password": hashed.hex(),
                    "salt": salt.hex(),
                }
            )
        )


def list_files(host, verify, user, groups):
    if groups == []:
        groups = ""
    result = requests.post(
        f"{host}/list",
        data={"user": user, "groups": groups},
        verify=verify,
    )
    print("User info:")
    print("username: " + user + ", groups: " + str(groups))
    print("Files:")
    print(result.text)


def download_cse(keyfile, host, output, verify, user, groups):
    if not os.path.isfile:
        print(
            "Error opening key file. Does it exist locally and do you have permissions to open it?"
        )
        sys.exit(1)
    with open(keyfile) as f:
        keydata = json.loads(f.read())

    password = getpass("Enter password to decrypt the key file: ")
    password = password.encode("utf-8")
    salt = bytes.fromhex(keydata["salt"])
    hashed = bytes.fromhex(keydata["password"])
    if hashed != bcrypt.hashpw(password, salt):
        print("Wrong password")
        sys.exit(1)
    master_key = search_master_key(keydata["key_id"])
    master_encryptor = get_encryptor(master_key, "chacha")
    dek_key = master_encryptor.decrypt(
        bytes.fromhex(keydata["key"]),
        b"",
        bytes.fromhex(keydata["nonce_key"]),
        bytes.fromhex(keydata["signature_key"]),
    )
    dek_encryptor = get_encryptor(dek_key, keydata["enc_algo"])

    try:
        result = requests.get(
            f'{host}/download/{keydata["uuid"]}', verify=verify)
        if result.status_code == 404:
            print("Error: the file doesn't exist on the server")
            sys.exit(1)
        if not result.ok:
            raise ConnectionError
    except:
        print(
            "Error downloading encrypted file. If you use self-signed TLS certificates, make sure to pass the -s option."
        )
        sys.exit(1)

    # to understand this format, look at to_upload in download_cse function above
    metalen = fromBytes(result.content[:4])
    metadata = result.content[4: 4 + metalen]
    data = result.content[metalen + 8:]
    try:
        plaintext = dek_encryptor.decrypt(
            data,
            metadata,
            bytes.fromhex(keydata["nonce_dek"]),
            bytes.fromhex(keydata["signature_dek"]),
        )
    except:
        print("Error: the file has been tampered with!")
        sys.exit(1)

    user_match = re.search(r"user=([^\s,]+)", metadata.decode("utf-8"))

    if user_match:
        user_value = user_match.group(1)
        if user_value != user:
            group_match = re.search(
                r"group=([^\s,]+)", metadata.decode("utf-8"))
            group_value = group_match.group(1)
            if group_value != "self" and group_value in groups:
                print(
                    "Downloading file from user: "
                    + user_value
                    + " because you belong to shared folder: "
                    + group_value
                    + ""
                )
                pass
            else:
                print(
                    f"Error: the file was uploaded by another user and you have no permission to download it"
                )
                exit()

    print(f'Received file with metadata: {metadata.decode("utf-8")}')

    # write the encrypted file to output if one was given,
    # or to the location of the keyfile without the .key ending
    with open(output if output else keyfile.split(".key")[0], "wb") as f:
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
            print(
                "{file} is neither a valid UUID nor a valid keyfile that could be opened."
            )
            sys.exit(1)

    result = requests.delete(f"{host}/delete/{uuid}", verify=verify)
    if result.status_code == 404:
        print("File does not exist on the server")
        sys.exit(1)
    elif not result.ok:
        print("There was an error deleting the file")
        sys.exit(1)

    print("File deleted successfully!")


def login(username):
    users = []
    with open("users.pkl", "rb") as f:
        users = pickle.load(f)
    for user in users:
        if username == user["username"]:
            print("Welcome to the secureCloud login system, " + username + "!")
            password = getpass("Please enter your password to login: ")
            password = password.encode("utf-8")
            salt = user["salt"]
            hashed = bcrypt.hashpw(password, salt)
            if hashed == user["password"]:
                print("Login successful!")
                return True, user["groups"]
            else:
                print("Login failed!")
                return False, []
    print("User not found!")
    return False, []


def main():
    parser = argparse.ArgumentParser(
        "secureCloud client",
        description="""
The client offers a few different modes that treat the FILE argument differently:

- upload (u): Encrypts a file and uploads it to the server. FILE is the path of said file. Creates a keyfile which is required to decrypt the file later. DO NOT UPLOAD, SHARE OR DELETE THIS FILE!
- donwload (d): Downlads a previously encrypted file from the server and decrypts it. FILE is the path of the keyfile created during upload.
- remove (r, delete): Securely erase a file from the server. FILE can be the keyfile generated by upload, or the file's UUID
    """,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "MODE",
        help="What to do.",
        choices=["upload", "u", "download", "d",
                 "delete", "remove", "r", "list", "l"],
    )
    parser.add_argument(
        "FILE",
        help="What file to operate on. Is a local filename in case of upload, file ID otherwise",
    )
    parser.add_argument(
        "-u",
        "--user",
        required=True,
        help="Username to use for authentication.",
    )
    parser.add_argument(
        "-e",
        "--encrypt",
        required=False,
        default="chacha",
        help="Encryption algorithm to use. Default: chacha",
        choices=list(aead_algorithms.keys()) +
        list(encryption_algorithms.keys()),
    )

    parser.add_argument(
        "-m",
        "--metadata",
        default=b"",
        help="Unencrypted but authenticated data to upload alongside file.",
    )
    parser.add_argument(
        "--host",
        default="https://localhost:443",
        help="Location of the server host. Default https://localhost:443",
    )
    parser.add_argument(
        "-s",
        "--skip-verify",
        action="store_true",
        required=False,
        help="Don't verify TLS certificates. Use only for local testing!",
    )
    parser.add_argument(
        "-o",
        "--output",
        required=False,
        help=" When downloading: Location to store file.\nWhen uploading: key file containing nessecary data to decrypt the file later when uploading. Default: <filename>.key",
    )
    parser.add_argument(
        "-f",
        "--shared-folder",
        required=False,
        help="When uploading: The group that the file will be shared with. Default: self (only the user can access the file).",
        default="self",
    )
    args = parser.parse_args()
    user = args.user
    login_suc, groups = login(user)
    if not login_suc:
        print("Login failed. Exiting.")
        sys.exit(1)

    if args.skip_verify:
        print("WARNING: Skipping TLS certificate verification. USE ONLY FOR TESTING!")

    # creating and adding a new shared folder
    if args.shared_folder != "self" and args.shared_folder not in groups:
        print("New shared folder: " + args.shared_folder)
        users = input(
            "Enter the users that you want to share the file with (separated by a comma): "
        )
        users = users.split(",")
        user_dict = []
        with open("users.pkl", "rb") as f:
            user_dict = pickle.load(f)
            for i in range(len(user_dict)):
                if user_dict[i]["username"] == user or user_dict[i]["username"] in users:
                    user_dict[i]["groups"].append(args.shared_folder)
                    user_dict[i]["groups"] = list(set(user_dict[i]["groups"]))
                    user_dict[i]["groups"].sort()

        with open("users.pkl", "wb") as f:
            print(user_dict)
            pickle.dump(user_dict, f)
            print("Shared folder created successfully!")

    if args.MODE == "u" or args.MODE == "upload":
        args.metadata = "user=" + str(args.user) + ", " + "date=" + str(datetime.datetime.utcnow(
        )) + ", " + "group=" + str(args.shared_folder) + ", " + "user-defined=" + str(args.metadata)
        args.metadata = args.metadata.encode("utf-8")
        upload_cse(
            args.FILE,
            args.metadata,
            args.host,
            args.output,
            not args.skip_verify,
            args.encrypt,
        )
    elif args.MODE == "d" or args.MODE == "download":
        download_cse(
            args.FILE, args.host, args.output, not args.skip_verify, user, groups
        )
    elif args.MODE == "r":
        delete(args.FILE, args.host, not args.skip_verify)
    elif args.MODE == "l":
        list_files(args.host, not args.skip_verify, user, groups)
    else:
        raise NotImplementedError()


if __name__ == "__main__":
    main()
