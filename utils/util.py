import json
import os

USER_FILE = 'data/users.json'

def load_users(file_path=USER_FILE):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return json.load(f)
    return []

def save_users(users, file_path=USER_FILE):
    with open(file_path, 'w') as f:
        json.dump(users, f, indent=4)
