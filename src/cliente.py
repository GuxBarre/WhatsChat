import flet as ft
import socket
import threading
import ssl
import json
import re
from security import DHManager 
from cryptography.hazmat.primitives import serialization

HOST = 'localhost'
PORT = 8000
MY_MSG_COLOR = ft.Colors.BLUE_900
OTHER_MSG_COLOR = ft.Colors.GREY_800

class SecureChatClient:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "WhatsChat Seguro"
        self.page.theme_mode = ft.ThemeMode.DARK
        self.sock = None
        self.dh_mgr = DHManager()
        self.running = False
        self.mode = "login"
        
        # --- UI ELEMENTS ---
        self.user_input = ft.TextField(label="Usuário", width=300, prefix_icon=ft.Icons.PERSON)
        self.pass_input = ft.TextField(label="Senha", password=True, can_reveal_password=True, width=300, prefix_icon=ft.Icons.KEY)
        self.login_btn = ft.ElevatedButton("Entrar", on_click=self.start_connection, width=300)
        self.to_reg_btn = ft.TextButton("Não tem conta? Cadastre-se", on_click=self.toggle_mode)
        
        self.login_col = ft.Column([
            ft.Text("Bem-vindo!", size=30), ft.Icon(ft.Icons.LOCK_OPEN, size=50, color=ft.Colors.BLUE),
            self.user_input, self.pass_input, self.login_btn, self.to_reg_btn
        ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER)

        self.reg_user = ft.TextField(label="Usuário", width=300, prefix_icon=ft.Icons.PERSON_ADD)
        self.reg_email = ft.TextField(label="Email", width=300, prefix_icon=ft.Icons.EMAIL)
        self.reg_phone = ft.TextField(label="Telefone", width=300, prefix_icon=ft.Icons.PHONE)
        self.reg_pass = ft.TextField(label="Senha", password=True, width=300, prefix_icon=ft.Icons.KEY)
        self.reg_conf = ft.TextField(label="Confirmar Senha", password=True, width=300, prefix_icon=ft.Icons.KEY_OFF)
        self.reg_btn = ft.ElevatedButton("Criar Conta", on_click=self.start_connection, width=300, bgcolor=ft.Colors.GREEN_700, color=ft.Colors.WHITE)
        self.to_log_btn = ft.TextButton("Já tenho conta. Fazer Login", on_click=self.toggle_mode)

        self.register_col = ft.Column([
            ft.Text("Criar Conta", size=30), self.reg_user, self.reg_email, self.reg_phone, 
            self.reg_pass, self.reg_conf, self.reg_btn, self.to_log_btn
        ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER, visible=False)

        self.chat_list = ft.ListView(expand=True, spacing=10, padding=20)
        self.msg_input = ft.TextField(hint_text="Mensagem...", expand=True, on_submit=self.send_message)
        self.send_btn = ft.IconButton(icon=ft.Icons.SEND, on_click=self.send_message)
        self.chat_view = ft.Column([
            ft.Container(content=self.chat_list, expand=True), 
            ft.Container(content=ft.Row([self.msg_input, self.send_btn]), padding=10, bgcolor=ft.Colors.GREY_900)
        ], visible=False, expand=True)

        self.status_text = ft.Text("Pronto.", color=ft.Colors.GREY)
        self.page.add(self.login_col, self.register_col, self.status_text, self.chat_view)

    # --- VALIDAÇÕES ---
    def validate_email(self, email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def validate_password_strength(self, password):
        if len(password) < 8: return False, "Mínimo de 8 caracteres."
        if not re.search(r"[A-Z]", password): return False, "Precisa de Maiúscula."
        if not re.search(r"[0-9]", password): return False, "Precisa de Número."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): return False, "Precisa de caractere Especial."
        return True, ""

    def show_error(self, message):
        self.page.snack_bar = ft.SnackBar(ft.Text(message), bgcolor=ft.Colors.RED)
        self.page.snack_bar.open = True
        self.page.update()

    def toggle_mode(self, e):
        self.mode = "register" if self.mode == "login" else "login"
        self.login_col.visible = (self.mode == "login")
        self.register_col.visible = (self.mode == "register")
        self.page.update()

    def start_connection(self, e):
        # Validação LOGIN (Adicionado .strip() para evitar espaços vazios)
        if self.mode == "login":
            if not self.user_input.value or not self.user_input.value.strip() or not self.pass_input.value:
                self.show_error("Preencha usuário e senha!")
                return

        # Validação REGISTRO
        if self.mode == "register":
            if not all([self.reg_user.value, self.reg_pass.value, self.reg_email.value]):
                self.show_error("Preencha todos os campos!")
                return
            if not self.validate_email(self.reg_email.value):
                self.show_error("E-mail inválido!")
                return
            if self.reg_pass.value != self.reg_conf.value:
                self.show_error("Senhas não conferem!")
                return
            valid, msg = self.validate_password_strength(self.reg_pass.value)
            if not valid:
                self.show_error(f"Senha fraca: {msg}")
                return

        self.status_text.value = "Conectando..."
        self.page.update()
        threading.Thread(target=self._connection_logic, daemon=True).start()

    def _connection_logic(self):
        try:
            if self.sock is None:
                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                context.load_cert_chain(certfile="certs/alice.crt", keyfile="certs/alice.key")
                context.load_verify_locations(cafile="certs/ca.crt")
                context.check_hostname = False
                raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock = context.wrap_socket(raw_sock, server_hostname=HOST)
                self.sock.connect((HOST, PORT))
                
                l = int.from_bytes(self.sock.recv(4), 'big'); p = self.sock.recv(l)
                server_params = serialization.load_pem_parameters(p)
                l = int.from_bytes(self.sock.recv(4), 'big'); k = self.sock.recv(l)
                my_k = self.dh_mgr.generate_private_key(server_params)
                self.sock.send(len(my_k).to_bytes(4, 'big')); self.sock.send(my_k)
                self.dh_mgr.compute_shared_secret(k)

            while True:
                data = self.sock.recv(4096).decode('utf-8')
                msg, valid = self.dh_mgr.verify_message(data)
                if not valid: return

                if msg == 'AUTH_REQ':
                    if self.mode == 'login':
                        pl = {'action':'login', 'u':self.user_input.value, 'p':self.pass_input.value}
                    else:
                        pl = {'action':'register', 'u':self.reg_user.value, 'p':self.reg_pass.value, 'email':self.reg_email.value, 'phone':self.reg_phone.value}
                    self.sock.send(self.dh_mgr.sign_message(json.dumps(pl)).encode('utf-8'))
                
                elif msg == 'AUTH_OK':
                    self.running = True
                    self.login_col.visible = False
                    self.chat_view.visible = True
                    self.page.update()
                    threading.Thread(target=self.receive_loop, daemon=True).start()
                    break

                elif msg == 'REG_OK':
                    self.show_error("Conta Criada! Faça Login.")
                    self.toggle_mode(None)
                
                elif "ERRO" in msg:
                    self.show_error(msg)
                    self.status_text.value = msg
                    self.page.update()

        except Exception as e:
            self.show_error(f"Erro: {e}")
            self.sock = None

    def send_message(self, e):
        txt = self.msg_input.value
        if txt:
            self.sock.send(self.dh_mgr.sign_message(txt).encode('utf-8'))
            align = ft.MainAxisAlignment.END
            self.chat_list.controls.append(ft.Row([ft.Container(content=ft.Text(f"Você: {txt}", color=ft.Colors.WHITE), bgcolor=MY_MSG_COLOR, padding=10, border_radius=10)], alignment=align))
            self.msg_input.value = ""; self.msg_input.focus(); self.page.update()

    def receive_loop(self):
        while self.running:
            try:
                data = self.sock.recv(4096).decode('utf-8')
                if not data: break
                msg, valid = self.dh_mgr.verify_message(data)
                if valid:
                    align = ft.MainAxisAlignment.START
                    self.chat_list.controls.append(ft.Row([ft.Container(content=ft.Text(msg, color=ft.Colors.WHITE), bgcolor=OTHER_MSG_COLOR, padding=10, border_radius=10)], alignment=align))
                    self.page.update()
            except: break

def main(page: ft.Page):
    client = SecureChatClient(page)

if __name__ == "__main__":
    ft.app(target=main)