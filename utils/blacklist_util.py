import json
import os

BLACKLIST_FILE = os.path.abspath('blacklist.json')


# Load blacklisted tokens
def load_blacklist():
    if not os.path.exists(BLACKLIST_FILE):
        return []
    try:
        with open(BLACKLIST_FILE, 'r') as file:
            content = file.read().strip()
            return json.loads(content) if content else []
    except json.JSONDecodeError:
        return []


# Save blacklisted tokens
def save_blacklist(tokens):
    with open(BLACKLIST_FILE, 'w') as file:
        json.dump(tokens, file)

# Add a token to blacklist
def add_to_blacklist(token):
    tokens = load_blacklist()
    if token not in tokens:
        tokens.append(token)
        save_blacklist(tokens)

# Check if token is blacklisted
def is_blacklisted(token):
    return token in load_blacklist()
