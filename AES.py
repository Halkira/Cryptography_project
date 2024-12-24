from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class AESCipher:
    def __init__(self):
        self.block_size = AES.block_size
        self.salt_length = 32

    def validate_path(self, path):
        """Vérifie si le chemin est valide et accessible"""
        try:
            abs_path = os.path.abspath(path)
            if os.path.exists(path):
                return abs_path
            parent_dir = os.path.dirname(abs_path)
            if os.path.exists(parent_dir):
                return abs_path
            print(f"Le chemin {path} n'est pas valide ou accessible.")
            return None
        except Exception as e:
            print(f"Erreur lors de la validation du chemin: {str(e)}")
            return None

    def derive_key(self, password, salt=None):
        """Dérive une clé AES à partir du mot de passe"""
        if salt is None:
            salt = os.urandom(self.salt_length)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return salt, key

    def encrypt_file(self, filepath, password):
        try:
            abs_path = self.validate_path(filepath)
            if not abs_path:
                return False

            with open(abs_path, 'rb') as f:
                data = f.read()

            salt, key = self.derive_key(password)
            cipher = AES.new(key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data, self.block_size))

            salt_b64 = base64.b64encode(salt).decode('utf-8')
            iv_b64 = base64.b64encode(cipher.iv).decode('utf-8')
            ct_b64 = base64.b64encode(ct_bytes).decode('utf-8')

            encrypted_data = f"{salt_b64}:{iv_b64}:{ct_b64}"
            output_path = abs_path + ".enc"

            with open(output_path, 'w') as f:
                f.write(encrypted_data)

            print(f"Fichier chiffré sauvegardé : {output_path}")
            return True

        except Exception as e:
            print(f"Erreur lors du chiffrement du fichier: {str(e)}")
            return False

    def decrypt_file(self, filepath, password):
        try:
            abs_path = self.validate_path(filepath)
            if not abs_path:
                return False

            with open(abs_path, 'r') as f:
                encrypted_data = f.read()

            salt_b64, iv_b64, ct_b64 = encrypted_data.split(':')
            salt = base64.b64decode(salt_b64)
            iv = base64.b64decode(iv_b64)
            ct = base64.b64decode(ct_b64)

            _, key = self.derive_key(password, salt)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), self.block_size)

            output_path = abs_path[:-4] if abs_path.endswith('.enc') else abs_path + '.dec'

            with open(output_path, 'wb') as f:
                f.write(pt)

            print(f"Fichier déchiffré sauvegardé : {output_path}")
            return True

        except Exception as e:
            print(f"Erreur lors du déchiffrement du fichier: {str(e)}")
            return False
