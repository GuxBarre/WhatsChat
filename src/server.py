import socket
import threading
import ssl
import json
from security import DHManager
from cryptography.hazmat.primitives import serialization
from authenticator import validate_login # <--- Importamos a autenticação

host = "0.0.0.0"
port = 8000

clients = []
users = []
client_security = {} 

# --- Configuração SSL (Igual ao anterior) ---
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="certs/server.crt", keyfile="certs/server.key")
context.load_verify_locations(cafile="certs/ca.crt")
context.verify_mode = ssl.CERT_REQUIRED

# --- GERA PARÂMETROS DH GLOBAIS ---
global_dh = DHManager()
server_params = global_dh.generate_parameters()

params_bytes = server_params.parameter_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.ParameterFormat.PKCS3
)

def broadcast(message_str, sender_conn=None):
    """Envia mensagem para todos. Se sender_conn for passado, não envia para ele."""
    for client in clients:
        if client != sender_conn:
            try:
                dh_mgr = client_security[client]
                signed_json = dh_mgr.sign_message(message_str)
                client.send(signed_json.encode('utf-8'))
            except:
                pass

def send_private(client, message_str):
    """Envia mensagem apenas para um cliente específico"""
    try:
        dh_mgr = client_security[client]
        signed_json = dh_mgr.sign_message(message_str)
        client.send(signed_json.encode('utf-8'))
    except:
        pass

def remove_client(client):
    if client in clients:
        try:
            index = clients.index(client)
            user = users[index]
            clients.remove(client)
            users.remove(user)
            del client_security[client]
            client.close()
            print(f"[LOG] {user} desconectou.")
            broadcast(f"--- {user} saiu do chat ---", None)
        except:
            pass

def handle(client):
    dh_mgr = client_security[client]
    
    while True:
        try:
            data = client.recv(4096).decode('utf-8')
            if not data:
                remove_client(client)
                break
            
            message, is_valid = dh_mgr.verify_message(data)
            index = clients.index(client)
            user = users[index]

            if not is_valid:
                print(f"[ALERTA] Integridade falhou para {user}")
                continue

            # --- COMANDO DE LISTAGEM ---
            if message.strip() == '/usuarios':
                lista = ", ".join(users)
                send_private(client, f"[SISTEMA] Usuários Online: {lista}")
            
            # --- MENSAGEM NORMAL ---
            else:
                print(f"[{user}]: {message}")
                msg_final = f"{user}: {message}"
                broadcast(msg_final, client) # Manda para os outros

        except:
            remove_client(client)
            break

def receive():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    print(f"[*] Servidor Seguro (mTLS + HMAC + Auth) rodando...")

    while True:
        try:
            client_socket, address = server.accept()
            conn = context.wrap_socket(client_socket, server_side=True)
            print(f"Conexão mTLS: {address}")

            # 1. Troca de Chaves DH
            dh_mgr = DHManager()
            my_pub_key = dh_mgr.generate_private_key(server_params)
            
            conn.send(len(params_bytes).to_bytes(4, 'big'))
            conn.send(params_bytes)
            conn.send(len(my_pub_key).to_bytes(4, 'big'))
            conn.send(my_pub_key)

            pub_len = int.from_bytes(conn.recv(4), 'big')
            client_pub_key = conn.recv(pub_len)
            dh_mgr.compute_shared_secret(client_pub_key)
            client_security[conn] = dh_mgr 
            
            # 2. LOGIN (Esperando JSON com user e pass)
            # Solicitamos credenciais
            req = dh_mgr.sign_message("LOGIN_REQ")
            conn.send(req.encode('utf-8'))
            
            # Recebe credenciais
            resp_json = conn.recv(4096).decode('utf-8')
            login_data_str, valid = dh_mgr.verify_message(resp_json)
            
            if valid:
                # O payload vem como string "user:senha", separamos aqui
                try:
                    login_data = json.loads(login_data_str)
                    u_try = login_data['u']
                    p_try = login_data['p']
                    
                    if validate_login(u_try, p_try):
                        if u_try in users:
                            # Evita usuário duplicado
                            error = dh_mgr.sign_message("ERRO: Usuário já conectado.")
                            conn.send(error.encode('utf-8'))
                            conn.close()
                            continue

                        users.append(u_try)
                        clients.append(conn)
                        print(f"Login SUCESSO: {u_try}")
                        
                        # Avisa sucesso
                        ok_msg = dh_mgr.sign_message("LOGIN_OK")
                        conn.send(ok_msg.encode('utf-8'))

                        # Thread de chat
                        thread = threading.Thread(target=handle, args=(conn,))
                        thread.start()
                        
                        broadcast(f"--- {u_try} entrou no chat ---", conn)
                    else:
                        print(f"Falha login: {u_try}")
                        conn.close()
                except:
                    conn.close()
            else:
                print("Integridade falhou no login.")
                conn.close()

        except Exception as e:
            print(f"Erro no accept: {e}")

if __name__ == "__main__":
    receive()