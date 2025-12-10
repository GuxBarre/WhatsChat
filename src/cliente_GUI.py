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

# --- PALETA DE CORES MODERNA ---
BG_COLOR = "#121212"       # Fundo da janela (Preto suave)
CARD_COLOR = "#1E1E1E"     # Fundo do cartão de login
INPUT_BG = "#2C2C2C"       # Fundo dos inputs
ACCENT_COLOR = ft.Colors.BLUE_600
MY_MSG_COLOR = "#005c4b"   # Verde estilo WhatsApp
OTHER_MSG_COLOR = "#202c33" # Cinza escuro

class SecureChatClient:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "WhatsChat Seguro"
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.bgcolor = BG_COLOR
        
        # --- CONFIGURAÇÃO DA JANELA (Tamanho de App) ---
        self.page.window_width = 400
        self.page.window_height = 750
        self.page.window_resizable = False  # Impede que fique gigante
        self.page.padding = 0
        self.page.vertical_alignment = ft.MainAxisAlignment.CENTER
        self.page.horizontal_alignment = ft.CrossAxisAlignment.CENTER

        self.sock = None
        self.dh_mgr = DHManager()
        self.running = False
        self.mode = "login"
        self.my_username = "" 
        
        # --- LOGO / CABEÇALHO ---
        self.logo = ft.Icon(ft.Icons.LOCK_PERSON_ROUNDED, size=80, color=ACCENT_COLOR)
        self.title_text = ft.Text("WhatsChat", size=24, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE)
        self.subtitle_text = ft.Text("Conexão mTLS + HMAC", size=12, color=ft.Colors.GREY_500)

        # --- ELEMENTOS DE FORMULÁRIO (Estilizados) ---
        def create_input(label, icon, password=False, reveal=False):
            return ft.TextField(
                label=label,
                prefix_icon=icon,
                password=password,
                can_reveal_password=reveal,
                border_radius=15,
                bgcolor=INPUT_BG,
                border_color=ft.Colors.TRANSPARENT,
                filled=True,
                text_size=14,
                content_padding=15
            )

        # Inputs de Login
        self.user_input = create_input("Usuário", ft.Icons.PERSON)
        self.pass_input = create_input("Senha", ft.Icons.KEY, True, True)
        
        # Inputs de Registro
        self.reg_user = create_input("Usuário", ft.Icons.PERSON_ADD)
        self.reg_email = create_input("Email", ft.Icons.EMAIL)
        self.reg_phone = create_input("Telefone", ft.Icons.PHONE)
        self.reg_pass = create_input("Senha", ft.Icons.KEY, True, False)
        self.reg_conf = create_input("Confirmar", ft.Icons.KEY_OFF, True, False)

        # Botões
        self.login_btn = ft.ElevatedButton(
            "ENTRAR", 
            on_click=self.start_connection, 
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=10),
                bgcolor=ACCENT_COLOR,
                color=ft.Colors.WHITE,
            ),
            height=45,
            width=280 # Largura fixa
        )
        
        self.reg_btn = ft.ElevatedButton(
            "CRIAR CONTA", 
            on_click=self.start_connection, 
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=10),
                bgcolor=ft.Colors.GREEN_700,
                color=ft.Colors.WHITE,
            ),
            height=45,
            width=280
        )

        self.to_reg_btn = ft.TextButton("Não tem conta? Cadastre-se", on_click=self.toggle_mode)
        self.to_log_btn = ft.TextButton("Já tenho conta. Fazer Login", on_click=self.toggle_mode)

        # --- CONTAINER DE LOGIN (O Cartão) ---
        self.login_card = ft.Container(
            content=ft.Column(
                [
                    self.logo,
                    self.title_text,
                    self.subtitle_text,
                    ft.Divider(height=20, color=ft.Colors.TRANSPARENT),
                    self.user_input,
                    self.pass_input,
                    ft.Divider(height=10, color=ft.Colors.TRANSPARENT),
                    self.login_btn,
                    self.to_reg_btn
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=10
            ),
            padding=30,
            border_radius=25,
            bgcolor=CARD_COLOR,
            width=320, # Largura do cartão
            shadow=ft.BoxShadow(blur_radius=20, color=ft.Colors.BLACK54)
        )

        # --- CONTAINER DE REGISTRO ---
        self.register_card = ft.Container(
            content=ft.Column(
                [
                    ft.Text("Nova Conta", size=22, weight=ft.FontWeight.BOLD),
                    ft.Divider(height=10, color=ft.Colors.TRANSPARENT),
                    self.reg_user,
                    self.reg_email,
                    self.reg_phone,
                    self.reg_pass,
                    self.reg_conf,
                    ft.Divider(height=10, color=ft.Colors.TRANSPARENT),
                    self.reg_btn,
                    self.to_log_btn
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=8, # Espaçamento menor para caber tudo
                scroll=ft.ScrollMode.HIDDEN # Permite rolar se a tela for pequena
            ),
            padding=30,
            border_radius=25,
            bgcolor=CARD_COLOR,
            width=320,
            shadow=ft.BoxShadow(blur_radius=20, color=ft.Colors.BLACK54),
            visible=False
        )

        # --- UI CHAT (Tela Cheia) ---
        self.chat_list = ft.ListView(expand=True, spacing=10, padding=15)
        self.msg_input = ft.TextField(
            hint_text="Mensagem...", 
            expand=True, 
            on_submit=self.send_message,
            border_radius=25,
            bgcolor=INPUT_BG,
            border_color=ft.Colors.TRANSPARENT,
            filled=True,
            content_padding=15
        )
        self.send_btn = ft.IconButton(
            icon=ft.Icons.SEND_ROUNDED, 
            icon_color=ACCENT_COLOR, 
            on_click=self.send_message,
            icon_size=30
        )
        
        self.chat_view = ft.Column(
            [
                # Barra Superior do Chat
                ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.LOCK, size=16, color=ft.Colors.GREEN),
                        ft.Text("Chat Criptografado", weight=ft.FontWeight.BOLD)
                    ], alignment=ft.MainAxisAlignment.CENTER),
                    padding=10,
                    bgcolor=CARD_COLOR
                ),
                ft.Container(content=self.chat_list, expand=True), 
                ft.Container(
                    content=ft.Row([self.msg_input, self.send_btn]), 
                    padding=10, 
                    bgcolor=CARD_COLOR
                )
            ],
            visible=False, 
            expand=True
        )

        self.status_text = ft.Text("Aguardando...", color=ft.Colors.GREY, size=12)
        
        # Adiciona os containers à pagina (usando Stack ou Column centralizada)
        self.main_layout = ft.Column(
            [
                self.login_card,
                self.register_card,
                ft.Container(content=self.status_text, margin=ft.margin.only(top=10))
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER
        )

        self.page.add(self.main_layout, self.chat_view)

    # --- LÓGICA DE VALIDAÇÃO ---
    def validate_email(self, email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def validate_password_strength(self, password):
        if len(password) < 8: return False, "Mínimo de 8 caracteres."
        if not re.search(r"[A-Z]", password): return False, "Falta letra MAIÚSCULA."
        if not re.search(r"[0-9]", password): return False, "Falta um NÚMERO."
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): return False, "Falta caractere ESPECIAL."
        return True, ""

    # --- UI HELPERS ---
    def show_error(self, message):
        self.page.snack_bar = ft.SnackBar(ft.Text(message), bgcolor=ft.Colors.RED_900)
        self.page.snack_bar.open = True
        self.page.update()

    def add_message_bubble(self, message, is_me=False):
        align = ft.MainAxisAlignment.END if is_me else ft.MainAxisAlignment.START
        bg = MY_MSG_COLOR if is_me else OTHER_MSG_COLOR
        border_r = ft.border_radius.only(
            top_left=15, top_right=15, 
            bottom_left=15 if is_me else 0, bottom_right=0 if is_me else 15
        )
        
        self.chat_list.controls.append(
            ft.Row([
                ft.Container(
                    content=ft.Text(message, color=ft.Colors.WHITE, size=15), 
                    bgcolor=bg, 
                    padding=12, 
                    border_radius=border_r,
                    constraints=ft.BoxConstraints(max_width=280)
                )
            ], alignment=align)
        )
        self.page.update()
        self.chat_list.scroll_to(offset=-1, duration=300)

    def toggle_mode(self, e):
        self.mode = "register" if self.mode == "login" else "login"
        self.login_card.visible = (self.mode == "login")
        self.register_card.visible = (self.mode == "register")
        self.page.update()

    def start_connection(self, e):
        # --- 1. VALIDAÇÃO DE REGISTRO ---
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
            is_strong, msg = self.validate_password_strength(self.reg_pass.value)
            if not is_strong:
                self.show_error(f"Senha Fraca: {msg}")
                return

        # --- 2. VALIDAÇÃO DE LOGIN (ISSO FALTAVA NO SEU CÓDIGO) ---
        if self.mode == "login":
            # O .strip() garante que espaço em branco não conta
            if not self.user_input.value or not self.user_input.value.strip():
                self.show_error("Digite o usuário!")
                return
            if not self.pass_input.value or not self.pass_input.value.strip():
                self.show_error("Digite a senha!")
                return

        # Se passou por tudo, conecta
        self.status_text.value = "Conectando..."
        self.status_text.color = ACCENT_COLOR
        self.login_btn.disabled = True # Evita duplo clique
        self.reg_btn.disabled = True
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
                
                # Handshake DH
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
                    self.my_username = self.user_input.value
                    self.running = True
                    self.main_layout.visible = False # Esconde login
                    self.chat_view.visible = True    # Mostra chat
                    self.page.window_width = 450     # Aumenta um pouco pra chat
                    self.page.update()
                    threading.Thread(target=self.receive_loop, daemon=True).start()
                    break

                elif msg == 'REG_OK':
                    self.show_error("Conta Criada! Faça Login.")
                    self.toggle_mode(None)
                
                elif "ERRO" in msg:
                    self.show_error(msg)
                    self.status_text.value = msg

        except Exception as e:
            self.show_error(f"Erro: {e}")
            self.sock = None

    def send_message(self, e):
        txt = self.msg_input.value
        if txt:
            self.sock.send(self.dh_mgr.sign_message(txt).encode('utf-8'))
            self.add_message_bubble(f"Você: {txt}", True)
            self.msg_input.value = ""
            self.msg_input.focus()
            self.page.update()

    def receive_loop(self):
        while self.running:
            try:
                data = self.sock.recv(4096).decode('utf-8')
                if not data: break
                msg, valid = self.dh_mgr.verify_message(data)
                if valid: self.add_message_bubble(msg, False)
            except: break

def main(page: ft.Page):
    client = SecureChatClient(page)

if __name__ == "__main__":
    ft.app(target=main)