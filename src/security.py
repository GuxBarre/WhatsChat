import hmac
import hashlib
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class DHManager:
    def __init__(self):
        self.private_key = None
        self.shared_key = None
        self.parameters = None

    def generate_parameters(self):
        print("Geração de parâmetros (Isso pode demorar alguns segundos)...")
        self.parameters = dh.generate_parameters(generator=2, key_size=2048)
        return self.parameters

    def generate_private_key(self, parameters=None):
        if parameters:
            self.parameters = parameters
        
        self.private_key = self.parameters.generate_private_key()
        public_key = self.private_key.public_key()
        
        # Serializa a chave pública para enviar pela rede (formato PEM)
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def compute_shared_secret(self, peer_public_key_bytes):
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
        
        shared_secret = self.private_key.exchange(peer_public_key)
        
        # Deriva uma chave simétrica limpa a partir do segredo matemático
        self.shared_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_secret)
        
        print(f"[DH] Segredo Compartilhado estabelecido!")
        return self.shared_key

    def sign_message(self, message):
        if not self.shared_key:
            raise Exception("Chave não estabelecida!")
            
        # Calcula HMAC-SHA256
        h = hmac.new(self.shared_key, message.encode('utf-8'), hashlib.sha256)
        signature = h.hexdigest()
        
        return json.dumps({
            "msg": message,
            "hmac": signature
        })

    def verify_message(self, json_data):
        """Valida se a mensagem foi adulterada"""
        try:
            data = json.loads(json_data)
            message = data['msg']
            received_hmac = data['hmac']
            
            # Recalcula HMAC
            h = hmac.new(self.shared_key, message.encode('utf-8'), hashlib.sha256)
            calculated_hmac = h.hexdigest()
            
            if hmac.compare_digest(calculated_hmac, received_hmac):
                return message, True # Íntegro
            else:
                return message, False # VIOLADO
        except:
            return None, False