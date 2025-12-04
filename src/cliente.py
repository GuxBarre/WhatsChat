import socket
import threading
import ssl
import sys
import json
import getpass # Para esconder a senha ao digitar
from security import DHManager
from cryptography.hazmat.primitives import serialization

HOST = 'localhost'
PORT = 8000

print("BEM VINDO AO WHATSCHAT SEGURO")
nickname = input("Usuário: ").strip()
password = getpass.getpass("Senha: ").strip()

# Configuração SSL
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_cert_chain(certfile="certs/alice.crt", keyfile="certs/alice.key")
context.load_verify_locations(cafile="certs/ca.crt")
context.check_hostname = False

try:
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client = context.wrap_socket(raw_socket, server_hostname=HOST)
    client.connect((HOST, PORT))
    
    # Troca de chaves Diffie-Hellman
    dh_mgr = DHManager()
    
    print("[*] Trocando chaves de criptografia...")
    param_len = int.from_bytes(client.recv(4), 'big')
    params_bytes = client.recv(param_len)
    server_params = serialization.load_pem_parameters(params_bytes)

    key_len = int.from_bytes(client.recv(4), 'big')
    server_pub_key = client.recv(key_len)

    my_pub_key = dh_mgr.generate_private_key(server_params)
    client.send(len(my_pub_key).to_bytes(4, 'big'))
    client.send(my_pub_key)

    dh_mgr.compute_shared_secret(server_pub_key)
    print("[*] Canal Integrado Estabelecido.")

except Exception as e:
    print(f"Erro conexão: {e}")
    sys.exit()

def receive():
    while True:
        try:
            data = client.recv(4096).decode('utf-8')
            message, valid = dh_mgr.verify_message(data)
            
            if not valid:
                print("[ALERTA SISTEMA] MENSAGEM CORROMPIDA RECEBIDA")
                continue

            # Protocolo de Login
            if message == 'LOGIN_REQ':
                # Envia User e Senha dentro do túnel seguro
                creds = json.dumps({'u': nickname, 'p': password})
                signed_creds = dh_mgr.sign_message(creds)
                client.send(signed_creds.encode('utf-8'))
            
            elif message == 'LOGIN_OK':
                print(f"\n Login aceito! Bem-vindo {nickname}.")
                print("Digite '/usuarios' para ver quem está online.\n")
            
            elif "ERRO:" in message:
                print(f"{message}")
                client.close()
                break
                
            else:
                print(message)
        except:
            print("Desconectado.")
            client.close()
            break

def write():
    while True:
        try:
            msg = input("")
            if msg:
                # Envia comando ou mensagem
                signed_msg = dh_mgr.sign_message(msg)
                client.send(signed_msg.encode('utf-8'))
        except:
            client.close()
            break

receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()