import argparse
import json
import os
import pickle
import re
import shutil
import signal
import threading
import time
from collections import defaultdict
from pathlib import Path
from threading import Lock

import bcrypt
import boto3
from bottle import Bottle, HTTPError, redirect, request, response, static_file
from cheroot.ssl.builtin import BuiltinSSLAdapter
from cheroot.wsgi import Server as WSGIServer
from werkzeug.utils import secure_filename

from encryption.AeadEncryptor import AeadEncryptor
from encryption.key_management import (create_or_reuse_master_key,
                                       generate_key, search_master_key)

storage_path: Path = Path(__file__).resolve().parent.parent / "server" / "storage"
chunk_path: Path = Path(__file__).resolve().parent.parent / "server" / "chunk"

allow_downloads = True
dropzone_cdn = "https://cdnjs.cloudflare.com/ajax/libs/dropzone"
dropzone_version = "5.7.6"
dropzone_timeout = "120000"
dropzone_max_file_size = "100000"
dropzone_chunk_size = "1000000"
dropzone_parallel_chunks = "true"
dropzone_force_chunking = "true"
mode = "sse"

lock = Lock()
chuncks = defaultdict(list)
app = Bottle()

# We read the credentials file
with open('../server/credentials.json') as cred_file:
    cred = json.load(cred_file)

# Create the kms client

session = boto3.Session(
    aws_access_key_id=cred["ACCESS_KEY_ID"],
    aws_secret_access_key=cred["SECRET_ACCESS_KEY"],
    region_name=cred["REGION_NAME"],
)
kms_client = session.client("kms")


def secure_erase(filename: str, passes=1):
    with open(filename, 'ab') as f:
        file_len = f.tell()
    with open(filename, 'wb') as f:
        for i in range(passes):
            f.seek(0)
            f.write(os.urandom(file_len))
    os.remove(filename)


@app.error(500)
def handle_500(error_message):
    response.status = 500
    response.body = f"Error: {error_message}"
    return response


@app.route("/")
def index():
    if mode == "cse":
        return "Server is running in CSE mode. Interface is not available."
    return f"""
<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="{dropzone_cdn.rstrip('/')}/{dropzone_version}/min/dropzone.min.css"/>
    <link rel="stylesheet" href="{dropzone_cdn.rstrip('/')}/{dropzone_version}/min/basic.min.css"/>
    <script type="application/javascript"
        src="{dropzone_cdn.rstrip('/')}/{dropzone_version}/min/dropzone.min.js">
    </script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/5.0.1/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">
    <title>Storage Server</title>
    <style>
      #content {{
        max-width: 800px;
        margin: 0 auto;
      }}
      h2 {{
        color: #007bff;
        margin-top: 30px;
        margin-bottom: 20px;
      }}
      #uploaded {{
        margin-top: 20px;
      }}
    </style>
</head>
<body>

     <div class="container" id="content">
      <h2><i class="fas fa-file-upload"></i> Upload new files</h2>
      <form method="POST" action="/upload" class="dropzone dz-clickable" id="dropper" enctype="multipart/form-data"></form>

      <h2>
        <i class="fas fa-upload"></i> Uploaded files
      </h2>
      <div id="uploaded"></div>
    </div>

        <script src="https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/5.0.1/js/bootstrap.min.js"></script>
        <script type="application/javascript">

            function generateLink(name,uuid){{
                if ({'true' if allow_downloads else 'false'}) {{
                    return `<div><p style="display: inline-block;">${{name}}</p><a class="btn btn-primary" href="/download/${{uuid}}" download="${{name}}" style="display: inline-block; margin-left: 10px;"><i class="fas fa-file-download"></i></a><a class="btn btn-danger" href="/delete/${{uuid}}" style="display: inline-block; margin-left: 10px;">
                        <i class="fas fa-trash"></i>
                    </a></div>`;
                }}
                return name;
            }}


            function init() {{
                fetch("https://localhost/list").then(response => response.json()).then(files => {{
                let content = "";
                files.forEach(file => {{
                if (!file.name.endsWith(".key")) {{
                    content += generateLink(file.name,file.uuid) + "<br />";
                }}
                }});
                document.getElementById("uploaded").innerHTML = content;
                }}).catch(error => console.log(error));
                
                Dropzone.options.dropper = {{
                    paramName: 'file',
                    chunking: true,
                    forceChunking: {dropzone_force_chunking},
                    url: '/upload',
                    retryChunks: true,
                    parallelChunkUploads: {dropzone_parallel_chunks},
                    timeout: {dropzone_timeout}, // microseconds
                    maxFilesize: {dropzone_max_file_size}, // megabytes
                    chunkSize: {dropzone_chunk_size}, // bytes
                    init: function () {{
                        this.on("complete", function (file) {{
                            document.getElementById("uploaded").innerHTML += generateLink(file.name,file.upload.uuid)  + "<br/>";
                        }});
                    }}
                }}

                if (typeof document.cookie !== 'undefined' ) {{
                    let content = "";
                     getFilesFromCookie().forEach(function (combo) {{
                        content += generateLink(combo) + "<br />";
                    }});

                    document.getElementById("uploaded").innerHTML = content;
                }}
            }}

            init();

        </script>
    </div>
</body>
</html>
    """

@app.route("/register", method="POST")
def register():
    users = []
    username = request.forms.get("username")
    password = request.forms.get("password")

    try:
        with open('../server/users.pkl', 'rb') as f:
            try:
                users = pickle.load(f)
            except EOFError:
                pass
    except FileNotFoundError:
        pass

    for user in users:
        if username == user['username']:
            return(f"Username already taken. Please try again.")
        
    password = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password, salt)

    users.append({'username': username, 'password': hashed, 'salt': salt})

    with open('../server/users.pkl', 'wb') as f:
        pickle.dump(users, f)
    
    return(f"User {username} successfully registered.")

@app.route("/login", method="POST")
def login():
    users = []
    username = request.forms.get("username")
    password = request.forms.get("password")

    try:
        with open('../server/users.pkl', 'rb') as f:
            try:
                users = pickle.load(f)
            except EOFError:
                pass
    except FileNotFoundError:
        pass

    for user in users:
        if username == user['username']:
            if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                return(f"User {username} successfully logged in.")
            else:
                return HTTPError(status=401)
    return HTTPError(status=404)


def find_uploaded_file(dz_uuid):
    if mode == "cse":
        for file in storage_path.iterdir():
            if file.is_file() and file.name.startswith(dz_uuid):
                return file
        return None
    else:
        for file in storage_path.iterdir():
            if file.is_file() and file.name.startswith(dz_uuid):
                if file.name.endswith(".key"):
                    keyfile = file
                else:
                    mainfile = file
        return mainfile, keyfile


@app.route("/upload", method="POST")
def upload():
    file = request.files.get("file")
    if not file:
        raise HTTPError(status=400, body="No file provided")

    dz_uuid = request.forms.get("dzuuid")

    # Chunked download
    try:
        current_chunk = int(request.forms["dzchunkindex"])
        total_chunks = int(request.forms["dztotalchunkcount"])
    except KeyError as err:
        raise HTTPError(
            status=400, body=f"Not all required fields supplied, missing {err}"
        )
    except ValueError:
        raise HTTPError(
            status=400, body=f"Values provided were not in expected format")

    save_dir = chunk_path / dz_uuid

    if not save_dir.exists():
        save_dir.mkdir(exist_ok=True, parents=True)

    if mode == "sse":
        dek_key = generate_key(kms_client, cred)
        dek_encryptor = AeadEncryptor(dek_key, "chacha")
        metadata = b""
        nonce_dek, encrypted, signature_dek = dek_encryptor.encrypt(
            file.file.read(), b""
        )

        with open(save_dir / str(current_chunk), "wb") as f:
            f.write(
                to_bytes(len(metadata))
                + metadata
                + to_bytes(len(encrypted))
                + encrypted
            )

        master_key, key_id = create_or_reuse_master_key()
        master_encryptor = AeadEncryptor(master_key, "chacha")
        key_nonce, key_encrypyted, key_signature = master_encryptor.encrypt(
            dek_key, b""
        )

        with open(
            storage_path /
                f"{dz_uuid}_{secure_filename(file.filename)}.key", "a+"
        ) as f:
            f.write(
                json.dumps(
                    {
                        "nonce_dek": nonce_dek.hex(),
                        "signature_dek": signature_dek.hex(),
                        "nonce_key": key_nonce.hex(),
                        "signature_key": key_signature.hex(),
                        "key": key_encrypyted.hex(),
                        "key_id": key_id,
                        "dzchunkindex": request.forms["dzchunkindex"],
                        "chunk_size": len(
                            to_bytes(len(metadata))
                            + metadata
                            + to_bytes(len(encrypted))
                            + encrypted
                        ),
                    }
                )
                + "\n"
            )

        # See if we have all the chunks downloaded
        with lock:
            chuncks[dz_uuid].append(current_chunk)
            completed = len(chuncks[dz_uuid]) == total_chunks

        # Concat all the files into the final file when all are downloaded
        if completed:
            with open(
                storage_path /
                    f"{dz_uuid}_{secure_filename(file.filename)}", "wb"
            ) as f:
                for file_number in range(total_chunks):
                    f.write((save_dir / str(file_number)).read_bytes())
            print(f"{file.filename} has been uploaded")
            shutil.rmtree(save_dir)
            return "File upload successful"

        return "Chunk upload successful"
    else:
        # Save the individual chunk
        with open(save_dir / str(request.forms["dzchunkindex"]), "wb") as f:
            file.save(f)

        # See if we have all the chunks downloaded
        with lock:
            chuncks[dz_uuid].append(current_chunk)
            completed = len(chuncks[dz_uuid]) == total_chunks

        # Concat all the files into the final file when all are downloaded
        if completed:
            file.filename = request.forms.get("filename")
            with open(
                storage_path /
                    f"{dz_uuid}_{secure_filename(file.filename)}", "wb"
            ) as f:
                for file_number in range(total_chunks):
                    f.write((save_dir / str(file_number)).read_bytes())
            print(f"{file.filename} has been uploaded")
            shutil.rmtree(save_dir)

        return "Chunk upload successful"


def to_bytes(num):
    return int.to_bytes(num, 4, "little")  # little endian


def fromBytes(bytes):
    return int.from_bytes(bytes, "little")  # little endian


def read_file_in_chunks(filename, chunk_size):
    with open(filename, "rb") as f:
        while True:
            chunk = f.read(int(chunk_size))
            if not chunk:
                break
            yield chunk


@app.route("/download/<dz_uuid>")
def download(dz_uuid):
    if not allow_downloads:
        return HTTPError(status=403)

    if not storage_path.exists():
        storage_path.mkdir(exist_ok=True, parents=True)

    if mode == "cse":
        file = find_uploaded_file(dz_uuid)
        return (
            static_file(file.name, root=file.parent.absolute(), download=True)
            if file
            else HTTPError(status=404)
        )

    file, keyfile = find_uploaded_file(dz_uuid)

    with open(keyfile, "r") as f:
        num_lines = sum(1 for line in f)

    if num_lines > 1:
        keys_dict = {}
        with open(keyfile) as f:
            for line in f:
                keydata = json.loads(line)
                keys_dict[keydata["dzchunkindex"]] = keydata
        # multiple keys found
        count = 0
        plaintext = b""
        with open(file, "rb") as f:
            while True:
                if count == num_lines:
                    break
                chunk = f.read(int(keys_dict[str(count)]["chunk_size"]))
                if not chunk:
                    break
                master_key = search_master_key(keys_dict[str(count)]["key_id"])
                master_encryptor = AeadEncryptor(master_key, "chacha")
                dek_key = master_encryptor.decrypt(
                    bytes.fromhex(keys_dict[str(count)]["key"]),
                    b"",
                    bytes.fromhex(keys_dict[str(count)]["nonce_key"]),
                    bytes.fromhex(keys_dict[str(count)]["signature_key"]),
                )
                dek_encryptor = AeadEncryptor(dek_key, "chacha")

                metalen = fromBytes(chunk[:4])
                metadata = chunk[4: 4 + metalen]
                data = chunk[metalen + 8:]
                plaintext += dek_encryptor.decrypt(
                    data,
                    metadata,
                    bytes.fromhex(keys_dict[str(count)]["nonce_dek"]),
                    bytes.fromhex(keys_dict[str(count)]["signature_dek"]),
                )
                count += 1
    else:
        with open(keyfile) as f:
            keydata = json.loads(f.read())

        master_key = search_master_key(keydata["key_id"])
        master_encryptor = AeadEncryptor(master_key, "chacha")
        dek_key = master_encryptor.decrypt(
            bytes.fromhex(keydata["key"]),
            b"",
            bytes.fromhex(keydata["nonce_key"]),
            bytes.fromhex(keydata["signature_key"]),
        )
        dek_encryptor = AeadEncryptor(dek_key, "chacha")

        result = file.read_bytes()
        metalen = fromBytes(result[:4])
        metadata = result[4: 4 + metalen]
        data = result[metalen + 8:]
        plaintext = dek_encryptor.decrypt(
            data,
            metadata,
            bytes.fromhex(keydata["nonce_dek"]),
            bytes.fromhex(keydata["signature_dek"]),
        )
    filename = keyfile.with_suffix("").name[37:]
    with open(keyfile.with_name(filename), "wb") as f:
        f.write(plaintext)
    response = static_file(
        keyfile.with_name(filename).name,
        root=storage_path,
        download=True,
    )

    t = threading.Thread(
        target=remove_file, args=(keyfile.with_name(filename),)
    )
    t.start()
    return response


def remove_file(file):
    time.sleep(2)
    print("Removing file", file)
    os.remove(file)


@app.route("/delete/<dz_uuid>", method="GET")
def delete(dz_uuid):
    if mode == "cse":
        print(f"Deleting file {dz_uuid}")
        file = find_uploaded_file(dz_uuid)
        if not file:
            return HTTPError(status=404)
        print(file.name)
        secure_erase(storage_path / file.name, 10)
        return "Deleted file securely"
    else:
        print(f"Deleting file {dz_uuid}...")
        file, keyfile = find_uploaded_file(dz_uuid)
        if not file:
            return HTTPError(status=404)
        secure_erase(storage_path / file.name, 10)
        secure_erase(storage_path / keyfile.name, 10)
        print(f"Deleted file securely")
        return redirect("/")

@app.route("/list", methods=["GET", "POST"])
def list_files():
    if request.method == "GET":
        files = []
        for file in storage_path.iterdir():
            if file.is_file():
                files.append(
                    {
                        "name": file.name[37:],
                        "uuid": file.name[:36],
                        "size": file.stat().st_size,
                    }
                )
        response.content_type = "application/json"
        return json.dumps(files)
        
    elif request.method == "POST":
        files = []
        user = request.POST.get("user")
        for file in storage_path.iterdir():
            if file.is_file():
                result = file.read_bytes()
                metalen = fromBytes(result[:4])
                metadata = result[4: 4 + metalen]
                print(metadata)
                user_match = re.search(r"user=([^\s,]+)", metadata.decode("utf-8"))
                user_value = user_match.group(1)
                if user_value == user:
                    files.append(
                        {
                            "name": file.name[37:],
                            "uuid": file.name[:36],
                            "size": str(file.stat().st_size) + " bytes"
                        }
                    )
            
        response.content_type = "application/json"
        return json.dumps(files)



def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", type=str,
                        default="sse", required=False)
    parser.add_argument(
        "-s", "--storage", type=str, default=str(storage_path), required=False
    )
    parser.add_argument(
        "-c", "--chunks", type=str, default=str(chunk_path), required=False
    )
    parser.add_argument(
        "--max-size",
        type=str,
        default=dropzone_max_file_size,
        help="Max file size (Mb)",
    )
    parser.add_argument(
        "--timeout",
        type=str,
        default=dropzone_timeout,
        help="Timeout (ms) for each chuck upload",
    )
    parser.add_argument(
        "--chunk-size", type=str, default=dropzone_chunk_size, help="Chunk size (bytes)"
    )
    parser.add_argument(
        "--disable-parallel-chunks", required=False, default=False, action="store_true"
    )
    parser.add_argument(
        "--disable-force-chunking", required=False, default=False, action="store_true"
    )
    parser.add_argument(
        "-a", "--allow-downloads", required=False, default=False, action="store_true"
    )
    parser.add_argument("--dz-cdn", type=str, default=None, required=False)
    parser.add_argument("--dz-version", type=str, default=None, required=False)
    return parser.parse_args()

# Delete all temporary files. Is called automatically when the sever is terminated


def delete_files(signum, frame):
    directory = storage_path
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        try:
            if os.path.isfile(file_path):
                secure_erase(file_path, 10)
                print(f"Deleted file: {file_path}")
        except Exception as e:
            print(f"Error deleting file {file_path}: {e}")


if __name__ == "__main__":
    args = parse_args()
    storage_path = Path(args.storage)
    chunk_path = Path(args.chunks)
    dropzone_chunk_size = args.chunk_size
    dropzone_timeout = args.timeout
    dropzone_max_file_size = args.max_size
    mode = args.mode
    try:
        if (
            int(dropzone_timeout) < 1
            or int(dropzone_chunk_size) < 1
            or int(dropzone_max_file_size) < 1
        ):
            raise Exception(
                "Invalid dropzone option, make sure max-size, timeout, and chunk-size are all positive"
            )
    except ValueError:
        raise Exception(
            "Invalid dropzone option, make sure max-size, timeout, and chunk-size are all integers"
        )

    if args.dz_cdn:
        dropzone_cdn = args.dz_cdn
    if args.dz_version:
        dropzone_version = args.dz_version
    if args.disable_parallel_chunks:
        dropzone_parallel_chunks = "false"
    if args.disable_force_chunking:
        dropzone_force_chunking = "false"
    if args.allow_downloads:
        allow_downloads = True

    if not storage_path.exists():
        storage_path.mkdir(exist_ok=True)
    if not chunk_path.exists():
        chunk_path.mkdir(exist_ok=True)

    print(
        f"""Timeout: {int(dropzone_timeout) // 1000} seconds per chunk
Chunk Size: {int(dropzone_chunk_size) // 1024} Kb
Max File Size: {int(dropzone_max_file_size)} Mb
Force Chunking: {dropzone_force_chunking}
Parallel Chunks: {dropzone_parallel_chunks}
Storage Path: {storage_path.absolute()}
Chunk Path: {chunk_path.absolute()}
"""
    )
    server = WSGIServer(("localhost", 443), app)
    server.ssl_adapter = BuiltinSSLAdapter(
        certificate="../server/adhoc.crt", private_key="../server/adhoc.key"
    )
    other_mode = "sse" if mode == "cse" else "cse"
    print(
        f"Server started on https://localhost/ in {mode.upper()} mode. You can change to {other_mode.upper()} mode by adding -m {other_mode} to the command line"
    )
    if mode == "cse":
        print(
            "Web interface is disabled in client-side encryption mode. Launch client.py with the desired mode"
        )

    signal.signal(signal.SIGINT, delete_files)
    server.start()
