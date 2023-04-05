from pathlib import Path
from threading import Lock
from collections import defaultdict
import shutil
import argparse
import uuid
from cheroot.wsgi import Server as WSGIServer
from cheroot.ssl.builtin import BuiltinSSLAdapter
import signal
from bottle import Bottle, route, run, request, error, response, HTTPError, static_file
from werkzeug.utils import secure_filename
import os
import json
from encryption.FileManager import FileManager

storage_path: Path = Path(__file__).parent / "storage"
chunk_path: Path = Path(__file__).parent / "chunk"

allow_downloads = True
dropzone_cdn = "https://cdnjs.cloudflare.com/ajax/libs/dropzone"
dropzone_version = "5.7.6"
dropzone_timeout = "120000"
dropzone_max_file_size = "100000"
dropzone_chunk_size = "1000000"
dropzone_parallel_chunks = "true"
dropzone_force_chunking = "true"

lock = Lock()
chuncks = defaultdict(list)
app = Bottle()
fm = FileManager()

def delete_files(signum, frame):
    directory = storage_path
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        try:
            if os.path.isfile(file_path):
                fm.secure_erase(file_path, 10)
                print(f"Deleted file: {file_path}")
        except Exception as e:
            print(f"Error deleting file {file_path}: {e}")

@app.error(500)
def handle_500(error_message):
    response.status = 500
    response.body = f"Error: {error_message}"
    return response


@app.route("/")
def index():
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


def find_uploaded_file(dz_uuid):
    for file in storage_path.iterdir():
        if file.is_file() and file.name.startswith(dz_uuid):
            return file
    return None
    

@app.route("/upload", method="POST")
def upload():
    file = request.files.get("file")
    if not file:
        raise HTTPError(status=400, body="No file provided")

    dz_uuid = request.forms.get("dzuuid")
    if not dz_uuid:
        # Assume this file has not been chunked
        with open(storage_path / f"{uuid.uuid4()}_{secure_filename(file.filename)}", "wb") as f:
            file.save(f)
        return "File Saved"

    # Chunked download
    try:
        current_chunk = int(request.forms["dzchunkindex"])
        total_chunks = int(request.forms["dztotalchunkcount"])
    except KeyError as err:
        raise HTTPError(
            status=400, body=f"Not all required fields supplied, missing {err}")
    except ValueError:
        raise HTTPError(
            status=400, body=f"Values provided were not in expected format")

    save_dir = chunk_path / dz_uuid

    if not save_dir.exists():
        save_dir.mkdir(exist_ok=True, parents=True)

    # Save the individual chunk
    with open(save_dir / str(request.forms["dzchunkindex"]), "wb") as f:
        file.save(f)

    # See if we have all the chunks downloaded
    with lock:
        chuncks[dz_uuid].append(current_chunk)
        completed = len(chuncks[dz_uuid]) == total_chunks

    # Concat all the files into the final file when all are downloaded
    if completed:
        with open(storage_path / f"{dz_uuid}_{secure_filename(file.filename)}", "wb") as f:
            for file_number in range(total_chunks):
                f.write((save_dir / str(file_number)).read_bytes())
        print(f"{file.filename} has been uploaded")
        shutil.rmtree(save_dir)

    return "Chunk upload successful"


@app.route("/download/<dz_uuid>")
def download(dz_uuid):
    if not allow_downloads:
        raise HTTPError(status=403)
    
    if not storage_path.exists():
        storage_path.mkdir(exist_ok=True, parents=True)

    file = find_uploaded_file(dz_uuid)
    return static_file(file.name, root=file.parent.absolute(), download=True) if file else HTTPError(status=404) 

@app.route("/delete/<dz_uuid>", method="DELETE")
def delete(dz_uuid):
    print(f"Deleting file {dz_uuid}")
    file = find_uploaded_file(dz_uuid)
    if not file:
        return HTTPError(status=404)
    print(file.name)
    fm.secure_erase(storage_path / file.name, 10)
    return "Deleted file securely"

@app.route("/list")
def list_files():
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

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--storage", type=str,
                        default=str(storage_path), required=False)
    parser.add_argument("-c", "--chunks", type=str,
                        default=str(chunk_path), required=False)
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
    parser.add_argument("--chunk-size", type=str,
                        default=dropzone_chunk_size, help="Chunk size (bytes)")
    parser.add_argument("--disable-parallel-chunks",
                        required=False, default=False, action="store_true")
    parser.add_argument("--disable-force-chunking",
                        required=False, default=False, action="store_true")
    parser.add_argument("-a", "--allow-downloads",
                        required=False, default=False, action="store_true")
    parser.add_argument("--dz-cdn", type=str, default=None, required=False)
    parser.add_argument("--dz-version", type=str, default=None, required=False)
    return parser.parse_args()


if __name__ == "__main__":

    args = parse_args()
    storage_path = Path(args.storage)
    chunk_path = Path(args.chunks)
    dropzone_chunk_size = args.chunk_size
    dropzone_timeout = args.timeout
    dropzone_max_file_size = args.max_size
    try:
        if int(dropzone_timeout) < 1 or int(dropzone_chunk_size) < 1 or int(dropzone_max_file_size) < 1:
            raise Exception(
                "Invalid dropzone option, make sure max-size, timeout, and chunk-size are all positive")
    except ValueError:
        raise Exception(
            "Invalid dropzone option, make sure max-size, timeout, and chunk-size are all integers")

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
    server = WSGIServer(('localhost', 443), app)
    server.ssl_adapter = BuiltinSSLAdapter(
        certificate='adhoc.crt',
        private_key='adhoc.key'
    )
    print("Server started and working with client side encryption. You do not need to do anything more here. Launch client.py with the desired mode")
    server.start()
    signal.signal(signal.SIGINT, delete_files)
    server.start()