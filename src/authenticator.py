import hashlib
import os

USER_DB = "users.txt"

def hash_password(pwd):
    return hashlib.sha256(pwd.encode('utf-8')).hexdigest()

def register_user(username, password):
    if user_exists(username):
        return False
    
    hashed_pwd = hash_password(password)
    with open(USER_DB, "a") as f:
        f.write(f"{username}:{hashed_pwd}\n")
    return True

def validate_login(username, password):
    if not os.path.exists(USER_DB):
        return False

    target_hash = hash_password(password)
    
    with open(USER_DB, "r") as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) == 2:
                db_user, db_pass = parts
                if db_user == username and db_pass == target_hash:
                    return True
    return False

def user_exists(username):
    if not os.path.exists(USER_DB):
        return False
        
    with open(USER_DB, "r") as f:
        for line in f:
            parts = line.strip().split(':')
            if parts and parts[0] == username:
                return True
    return False