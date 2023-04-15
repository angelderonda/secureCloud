## INSTALLATION ⚙️

In Windows:
```
python -m venv env
.\env\Scripts\activate.bat      #Command prompt
.\env\Scripts\Activate.ps1      #Powershell
pip install -r requirements.txt
```

In Linux:
```
python -m venv env
./env/Scripts/activate
pip install -r requirements.txt
```

Then, you must create a `credentials.json` file in the root directory like this: 

```
{
  "ACCESS_KEY_ID": "YOUR_ACCESS_KEY_ID",
  "SECRET_ACCESS_KEY": "YOUR_SECRET_ACCESS_KEY",
  "REGION_NAME": "YOUR_AWS_REGION",
  "KEY_ID":"YOUR_KMS_KEY"
}
```

Remember that we are using AMS KMS so you will need to create an AWS account and set up a Customer Master Key (CMK) in KMS. You can find more information [here](https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html).

Before launching the application, you must generate a certificate and a private key in `src` folder using openssl (if you are using Windows, you can download [here](https://slproweb.com/download/Win64OpenSSL_Light-3_1_0.exe)). You can do it like this (keep in mind that if you change the name of the files, you will have to change the name in the code on `src/server.py` line 634):

```
openssl genpkey -algorithm RSA -out adhoc.key
openssl req -new -x509 -key adhoc.key -out adhoc.crt -days 3650
```
## STRUCTURE 📁

The python scripts are stored in `src` folder. In this folder, we can find:

- `client.py`: File with the client's code. This script is used in CSE to send the data to the server.
- `server.py`: File with the server's code. This script is used in the server to receive the data and process it and it is always running.
- `register.py`: File with the code to register a new user.
- `encryption`: Folder with the code to encrypt and decrypt the data.

The rest of the structure of the project can be found in `server`. This folder contains the info managed by the server. In this folder, we can find:
- `adhoc.crt`: Certificate file.
- `adhoc.key`: Private key file.
- `credentials.json`: File with the credentials to access AWS.
- `users.pkl`: File with the users' information (it is generated after a user is created and registered).
- `chunk`: Folder with the temporary chunks of the data uploaded to the server.
- `storage`: Folder with the encrypted data uploaded to the server (encrypted by the client in CSE and by the server in SSE). In the case of SSE, it also stores the encrypted DEK needed to decrypt the data divided in chunks.
- `keys`: Folder with the master keys used to encrypt the DEKs in SSE and CSE.


## APPLICATION 🌐

You can launch the application in two modes: CSE and SSE.

### CSE

In CSE, the client encrypts the data with a DEK provided by AWS KMS service and sends it to the server. The server stores it in the `storage` folder and the client can download it, decrypt it and use it.

First, you need to launch the server in CSE mode:

```python
cd src
python server.py -m cse
```

#### User registration
The next step is to register a new user to use the client.

```python
python register.py
```

The script will ask you for your username and password and it will make a request to the server to create yout specified user. The information of all users is stored in `users.pkl` file.

#### Client script

Then, you can launch the client script. The client script is a single use file that can be called with a wide range of options:

#### Uploading and Dowloading a file

To upload a file to the server, you can use the following command:

```python
python client.py u <file> -s -m <user_defined_metadata> -e <encryption_mode>
```

You can find more information about the options running help:

```python
python client.py -h
```
In the upload process, the script will ask you for your login credentials. Then, it will encrypt the file with the DEK provided by AWS KMS service and send it to the server. The server will store it in the `storage` folder and it will also give you a key file with the encrypted DEK.

To download a file from the server, you need to be the user that has uploaded the file, or belong to the same group. You also need the previous key file generated. You can use the following command:

```python
python client.py d <keyfile> -s -o <output_file>
```	

You do not need to specify group nor encryption mode in the download process, since the server will use the information stored in the key file and the metadata to decrypt the file.

#### List files

You can list all the files uploaded to the server using the following command:

```python
python client.py l -s
```

#### Removing a file

You can remove a file from the server using the following command:

```python
python client.py r <keyfile>/<uuid> -s
```

It will ask you for your login credentials. Then, it will remove the file from the server in a secure way.

### SSE

In SSE, the client encrypts the data with a DEK provided by AWS KMS service and sends it to the server. The server encrypts the DEK with a master key and stores it in the `storage` folder. The client can download it, decrypt it and use it.

For that, the server uses TLS to encrypt the communication between the client and the server. The server also uses a master key to encrypt the DEKs. The master key is stored in the `keys` folder.

First, you need to launch the server in SSE mode:

```python
cd src
python server.py -m sse
```

You can specify different options like the storage path, the chunk path, max file size, chunk size, allowing parallel chunk uploads, etc. You can find more information about the options running help:

```python
python server.py -h
```

It will be listening [here](https://localhost). There, you can upload and download files using the web interface.