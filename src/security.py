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
        if parameters: self.parameters = parameters
        self.private_key = self.parameters.generate_private_key()
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def compute_shared_secret(self, peer_public_key_bytes):
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
        shared_secret = self.private_key.exchange(peer_public_key)
        self.shared_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data'
        ).derive(shared_secret)
        return self.shared_key

    def sign_message(self, message):
        if not self.shared_key: raise Exception("Chave não estabelecida!")
        h = hmac.new(self.shared_key, message.encode('utf-8'), hashlib.sha256)
        return json.dumps({"msg": message, "hmac": h.hexdigest()})

    def verify_message(self, json_data):
        try:
            data = json.loads(json_data)
            h = hmac.new(self.shared_key, data['msg'].encode('utf-8'), hashlib.sha256)
            if hmac.compare_digest(h.hexdigest(), data['hmac']):
                return data['msg'], True
            return data['msg'], False
        except: return None, False