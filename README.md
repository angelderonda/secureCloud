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
pip install -r requirements.txt (dont worry about the errors)
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


## PLATFORM 🌐
