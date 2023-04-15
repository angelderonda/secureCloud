import json
import os
import re
from pathlib import Path

def create_or_reuse_master_key():
    # Define the directory containing the key files
    key_dir = Path(__file__).resolve().parent.parent.parent / "server" / "keys"

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
    key_dir = Path(__file__).resolve().parent.parent.parent / "server" / "keys"
    # Load the contents of the file
    with open(os.path.join(key_dir,f"key{id}.json"), "r") as f:
        master_key_data = json.load(f)
    master_key = bytes(master_key_data["master_key"])
    return master_key


def generate_key(kms_client, cred):
    # Generate new key
    response = kms_client.generate_data_key(
        KeyId=cred["KEY_ID"], KeySpec="AES_256")
    return response["Plaintext"]