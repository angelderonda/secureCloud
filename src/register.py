from getpass import getpass

import requests
import urllib3

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

input("Welcome to the registration page. Press enter to continue.")
username = input("Please enter a username: ")

password = getpass("Please enter a password: ")
password2 = getpass("Please enter your password again: ")

while password != password2:
    print("Passwords do not match. Please try again.")
    password = getpass("Please enter a password: ")
    password2 = getpass("Please enter your password again: ")

request = requests.post(
    f"https://localhost/register",
    data={"username": username, "password": password},
    verify=False,
)
print(request.text)
