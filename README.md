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

REVISAR DONDE METER EL CREDENTIALS.JSON EN LA VERSIÓN FINAL

Then, you must create a `credentials.json` file in the root directory like this: 

```
{
  "ACCESS_KEY_ID": "YOUR_ACCESS_KEY_ID",
  "SECRET_ACCESS_KEY": "YOUR_SECRET_ACCESS_KEY",
  "REGION_NAME": "YOUR_AWS_REGION",
  "KEY_ID":"YOUR_KMS_KEY"
}


```

Remember that we are using AMS KMS so you will need to create an AWS account.

Before launching the application, you must generate a certificate and a private key in `server` folder using openssl (if you are using Windows, you can download [here](https://slproweb.com/download/Win64OpenSSL_Light-3_1_0.exe)). You can do it like this:

```
openssl genpkey -algorithm RSA -out adhoc.key
openssl req -new -x509 -key adhoc.key -out adhoc.crt -days 3650
```

## APPLICATION 🌐

To launch the application, you must run the following commands:

```
cd server
python app.py
```

It will be listening [here](https://localhost).