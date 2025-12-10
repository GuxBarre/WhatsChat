import socket
import threading
import ssl
import json
from security import DHManager 
from authenticator import validate_login, register_user, user_exists 
from cryptography.hazmat.primitives import serialization

host = "0.0.0.0"
port = 8000
clients = []
users = []
client_security = {} 

# Configurações de Segurança
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="certs/server.crt", keyfile="certs/server.key")
context.load_verify_locations(cafile="certs/ca.crt")
context.verify_mode = ssl.CERT_REQUIRED

global_dh = DHManager()
server_params = global_dh.generate_parameters()
params_bytes = server_params.parameter_bytes(
    encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3
)

def broadcast(message_str, sender_conn=None):
    for client in clients:
        if client != sender_conn:
            try:
                dh_mgr = client_security[client]
                client.send(dh_mgr.sign_message(message_str).encode('utf-8'))
            except: pass

def handle(client):
    dh_mgr = client_security[client]
    while True:
        try:
            data = client.recv(4096).decode('utf-8')
            if not data: break
            
            message, is_valid = dh_mgr.verify_message(data)
            index = clients.index(client)
            user = users[index]

            if not is_valid:
                print(f"[ALERTA] Integridade falhou para {user}")
                continue

            if message == '/usuarios':
                lista = ", ".join(users)
                client.send(dh_mgr.sign_message(f"[SISTEMA] Online: {lista}").encode('utf-8'))
            else:
                print(f"[{user}]: {message}")
                broadcast(f"{user}: {message}", client)
        except: break
    
    # Remove cliente ao sair do loop
    if client in clients:
        idx = clients.index(client)
        u = users[idx]
        clients.remove(client)
        users.remove(u)
        del client_security[client]
        print(f"[LOG] {u} saiu.")
        broadcast(f"{u} saiu do chat.", None)
        client.close()

def receive():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    # SE ESSA MENSAGEM NAO APARECER, VOCE ESTA RODANDO O ARQUIVO ERRADO
    print(f"[*] Servidor Seguro (mTLS + HMAC + Registro) rodando...")

    while True:
        try:
            client, addr = server.accept()
            conn = context.wrap_socket(client, server_side=True)
            
            # 1. Troca de Chaves
            dh = DHManager()
            pub = dh.generate_private_key(server_params)
            conn.send(len(params_bytes).to_bytes(4, 'big')); conn.send(params_bytes)
            conn.send(len(pub).to_bytes(4, 'big')); conn.send(pub)
            
            l = int.from_bytes(conn.recv(4), 'big')
            client_pub = conn.recv(l)
            dh.compute_shared_secret(client_pub)
            client_security[conn] = dh
            
            # 2. Loop de Autenticação
            autenticado = False
            while not autenticado:
                conn.send(dh.sign_message("AUTH_REQ").encode('utf-8'))
                resp = conn.recv(4096).decode('utf-8')
                payload_str, valid = dh.verify_message(resp)
                
                if valid:
                    data = json.loads(payload_str)
                    action = data.get('action')
                    
                    if action == 'login':
                        u = data['u']
                        if validate_login(u, data['p']):
                            if u in users:
                                conn.send(dh.sign_message("ERRO: Usuário já conectado.").encode('utf-8'))
                            else:
                                users.append(u); clients.append(conn)
                                print(f"Login OK: {u}")
                                conn.send(dh.sign_message("AUTH_OK").encode('utf-8'))
                                autenticado = True
                                threading.Thread(target=handle, args=(conn,)).start()
                                broadcast(f"{u} entrou!", conn)
                        else:
                            conn.send(dh.sign_message("ERRO: Dados inválidos.").encode('utf-8'))
                            
                    elif action == 'register':
                        u = data['u']
                        if user_exists(u):
                            conn.send(dh.sign_message("ERRO: Usuário já existe.").encode('utf-8'))
                        else:
                            register_user(u, data['p'], data['email'], data['phone'])
                            print(f"Registrado: {u}")
                            conn.send(dh.sign_message("REG_OK").encode('utf-8'))
                else:
                    conn.close(); break
        except Exception as e:
            print(f"Erro: {e}")

if __name__ == "__main__":
    receive()