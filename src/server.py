import socket
import threading

host = "localhost"
port = 8000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Inicializador do socket
server.bind((host, port))   # Vincula o socket ao host e porta especificados
server.listen

clients = []  
nicknames = []


def broadcast(message):
    for client in clients:
        client.send(message)

def handle(client):
    while True:
        try:
            message = client.recv(1024)
            if not message:
                # Força uma exceção para tratar a desconexão do cliente
                raise Exception("Cliente desconectado")
            broadcast(message)
        except:
            # Erro ou desconexão do cliente
            index = clients.index(client)
            clients.remove(client)
            client.close()


def receive():
    while True:
        client, address = server.accept()
        print(f"Conectado com {str(address)}")
        client.send("Nome de Usuário".encode("utf-8"))
        nicknames = client.recv(1024).decode("utf-8")
        nicknames.append(nicknames)

        clients.append(client)
        print(f"Nome de Usuário é {nicknames}")
        broadcast(f"{nicknames} entrou no chat!".encode("utf-8"))
        client.send("Conectado ao servidor!".encode("utf-8"))
        theread = threading.Thread(target=handle, args=(client,))
        theread.start()

    receive()