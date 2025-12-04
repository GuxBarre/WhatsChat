from src.authenticator import register_user

print("--- CADASTRO DE USUÁRIOS ---")
while True:
    user = input("Novo Usuário (ou ENTER para sair): ").strip()
    if not user: break
    
    pwd = input(f"Senha para {user}: ").strip()
    
    if register_user(user, pwd):
        print(f"SUCESSO! Usuário {user} cadastrado!")
    else:
        print(f"ERRO: {user} já existe.")