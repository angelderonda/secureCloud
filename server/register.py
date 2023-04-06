import bcrypt
import pickle

users = []

try:
    with open('users.pkl', 'rb') as f:
        try:
            users = pickle.load(f)
        except EOFError:
            pass
except FileNotFoundError:
    pass

input ("Welcome to the registration page. Press enter to continue.")
username = input("Please enter a username: ")

for user in users:
    if username == user['username']:
        print("Username already taken. Please try again.")
        exit()

password = input("Please enter a password: ")
password2 = input("Please enter your password again: ")

if password != password2:
    print("Passwords do not match. Please try again.")
    exit()

password = password.encode('utf-8')
salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password, salt)

groups = []
group_val = input("Please enter groups to join (separated by commas): ")
if group_val != "":
    groups_input = group_val.split(",")
    for group in groups_input:
        groups.append(group.strip())

users.append({'username': username, 'password': hashed, 'salt': salt, 'groups': groups})

with open('users.pkl', 'wb') as f:
    pickle.dump(users, f)