import random
import string
import json
import base64
import time
import getpass

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import scrypt, PBKDF2
from Crypto.Random import get_random_bytes

def encrypt_rsa(message, public_key):
    """
    Chiffre un message avec RSA
    """
    try:
        # Conversion du message en bytes si nécessaire
        if isinstance(message, str):
            message = message.encode('utf-8')

        # Conversion de la clé publique en bytes si nécessaire
        if isinstance(public_key, str):
            public_key = public_key.encode('utf-8')

        # Import de la clé publique
        key = RSA.import_key(public_key)

        # Création du chiffreur
        cipher = PKCS1_OAEP.new(key)

        # Chiffrement du message
        encrypted = cipher.encrypt(message)

        # Encodage en base64
        return base64.b64encode(encrypted).decode('utf-8')

    except Exception as e:
        print(f"Erreur lors du chiffrement RSA : {e}")
        return None

def decrypt_rsa(encrypted_message, private_key):
    """
    Déchiffre un message avec RSA
    """
    try:
        # Décodage du message base64
        encrypted = base64.b64decode(encrypted_message)
        # Import de la clé privée
        if isinstance(private_key, str):
            key = RSA.import_key(private_key)
        else:
            key = private_key
        # Création du déchiffreur
        cipher = PKCS1_OAEP.new(key)
        # Déchiffrement
        decrypted = cipher.decrypt(encrypted)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"Erreur lors du déchiffrement RSA : {e}")
        return None

class KeyManager:
    def __init__(self):
        # Paramètres pour la dérivation de clé
        self.SCRYPT_PARAMS = {
            'N': 2 ** 14,
            'r': 8,
            'p': 1
        }
        self.field_map = None

    def _gen_random_blob(self):
        """Génère une structure aléatoire pour masquer les vraies données"""
        def random_string(length):
            return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

        # Création d'une structure avec 20-30 champs aléatoires
        num_fields = random.randint(20, 30)
        structure = {}
        field_names = []

        for _ in range(num_fields):
            field_name = random_string(random.randint(8, 16))
            field_names.append(field_name)
            structure[field_name] = random_string(random.randint(64, 256))

        return structure, field_names

    def decrypt_private_key(self, password, encrypted_data):
        """Déchiffre la clé privée"""
        try:
            # Chargement des données chiffrées
            data = json.loads(encrypted_data)

            # Récupération du sel maître
            salt_master = base64.b64decode(data[self.field_map['salt']])

            # Dérivation des clés
            password_bytes = password.encode('utf-8')
            key_data = scrypt(password_bytes, salt_master, 32, **self.SCRYPT_PARAMS)

            # Déchiffrement des données
            cipher = AES.new(
                key_data,
                AES.MODE_GCM,
                nonce=base64.b64decode(data[self.field_map['nonce']])
            )

            decrypted_data = cipher.decrypt_and_verify(
                base64.b64decode(data[self.field_map['data']]),
                base64.b64decode(data[self.field_map['tag']])
            )

            # Chargement des données déchiffrées
            json_data = json.loads(decrypted_data.decode('utf-8'))
            private_key_str = json_data['key']

            # Import de la clé privée avec le mot de passe
            return RSA.import_key(private_key_str, passphrase=password)

        except Exception as e:
            print(f"Erreur lors du déchiffrement de la clé privée : {e}")
            return None

    @staticmethod
    def decrypt_file(filename, password):
        """Déchiffre un fichier"""
        try:
            with open(filename, "rb") as f:
                file_salt = f.read(32)
                nonce = f.read(16)
                tag = f.read(16)
                ciphertext = f.read()

            # Dérivation de la clé
            key = scrypt(
                password.encode('utf-8'),
                file_salt,
                32,
                N=2 ** 14,
                r=8,
                p=1
            )

            # Déchiffrement
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            try:
                decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
                return json.loads(decrypted_data.decode('utf-8'))
            except (ValueError, KeyError) as e:
                print(f"Erreur de déchiffrement : {e}")
                return None

        except Exception as e:
            print(f"Erreur lors de la lecture du fichier : {e}")
            return None

    def generate_keys(self, key_password, file_password):
        try:
            # Génération de la structure aléatoire
            fake_structure, field_names = self._gen_random_blob()

            # Sélection des champs pour les vraies données
            real_fields = random.sample(field_names, 5)
            self.field_map = {
                'data': real_fields[0],
                'struct': real_fields[1],
                'salt': real_fields[2],
                'nonce': real_fields[3],
                'tag': real_fields[4]
            }

            # Préparation du mot de passe de la clé
            key_password_bytes = key_password.encode('utf-8')

            # Génération des clés RSA
            key = RSA.generate(4096)
            private_key = key.export_key(passphrase=key_password, pkcs=8,
                                       protection="scryptAndAES256-CBC")
            public_key = key.publickey().export_key()

            # Génération du sel et dérivation des clés
            salt_master = get_random_bytes(32)
            keys = {
                'data': scrypt(key_password_bytes, salt_master, 32, **self.SCRYPT_PARAMS),
                'structure': scrypt(key_password_bytes + b'_struct', salt_master, 32,
                                  **self.SCRYPT_PARAMS)
            }

            # Chiffrement de la clé privée
            cipher_data = AES.new(keys['data'], AES.MODE_GCM)
            data_to_encrypt = {
                'key': private_key.decode('utf-8'),
                'map': self.field_map,
                'version': base64.b64encode(get_random_bytes(8)).decode('utf-8'),
                'timestamp': str(time.time())
            }
            ciphertext_data, tag_data = cipher_data.encrypt_and_digest(
                json.dumps(data_to_encrypt).encode('utf-8')
            )

            # Construction de la structure finale
            fake_structure[self.field_map['data']] = base64.b64encode(ciphertext_data).decode('utf-8')
            fake_structure[self.field_map['salt']] = base64.b64encode(salt_master).decode('utf-8')
            fake_structure[self.field_map['nonce']] = base64.b64encode(cipher_data.nonce).decode('utf-8')
            fake_structure[self.field_map['tag']] = base64.b64encode(tag_data).decode('utf-8')

            # Conversion en JSON pour le chiffrement final
            json_data = json.dumps(fake_structure)

            # Chiffrement du fichier avec le second mot de passe
            file_password_bytes = file_password.encode('utf-8')
            file_salt = get_random_bytes(32)
            file_key = scrypt(file_password_bytes, file_salt, 32, **self.SCRYPT_PARAMS)

            cipher = AES.new(file_key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(json_data.encode('utf-8'))

            # Sauvegarde du fichier chiffré
            with open("private_key.enc", "wb") as f:
                [f.write(x) for x in (file_salt, cipher.nonce, tag, ciphertext)]

            # Sauvegarde de la clé publique
            with open("public_key.pem", "wb") as f:
                f.write(public_key)

            return True

        except Exception as e:
            print(f"Erreur lors de la génération des clés : {e}")
            return False
