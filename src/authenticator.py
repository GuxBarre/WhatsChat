import hashlib
import os

USER_DB = "users.txt"

def hash_password(pwd):
    return hashlib.sha256(pwd.encode('utf-8')).hexdigest()

def register_user(username, password, email, phone):
    """Salva usuário com dados extras: user:hash:email:phone"""
    if user_exists(username):
        return False
    
    hashed_pwd = hash_password(password)
    # Formato: usuario:senha_hash:email:telefone
    with open(USER_DB, "a", encoding='utf-8') as f:
        f.write(f"{username}:{hashed_pwd}:{email}:{phone}\n")
    return True

def validate_login(username, password):
    if not os.path.exists(USER_DB):
        return False

    target_hash = hash_password(password)
    
    with open(USER_DB, "r", encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) >= 2:
                db_user = parts[0]
                db_pass = parts[1]
                if db_user == username and db_pass == target_hash:
                    return True
    return False

def user_exists(username):
    if not os.path.exists(USER_DB):
        return False
        
    with open(USER_DB, "r", encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(':')
            if parts and parts[0] == username:
                return True
    return False