from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import json
from Crypto.Protocol.KDF import scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import traceback


class KeyManager:
    def __init__(self):
        self.SCRYPT_PARAMS = {
            'N': 2 ** 14,
            'r': 8,
            'p': 1
        }
        self.NB_LAYERS = 50  # Ajout de cette ligne
        self.field_maps = [None] * self.NB_LAYERS  # Utilisation de NB_LAYERS ici

    def generate_key_pair(self, key_password):
        """Génère une nouvelle paire de clés RSA"""
        try:
            # Génération de la paire de clés RSA
            key = RSA.generate(2048)

            # Export de la clé privée avec mot de passe
            private_key = key.export_key(passphrase=key_password)
            public_key = key.publickey().export_key()

            return private_key, public_key
        except Exception as e:
            print(f"Erreur lors de la génération des clés : {e}")
            return None, None

    def encrypt_layer(self, data, password, layer_number):
        """Chiffre une couche spécifique"""
        try:
            # Génération d'un sel aléatoire
            salt = get_random_bytes(32)

            # Dérivation de la clé pour cette couche
            layer_key = scrypt(
                password.encode('utf-8') + bytes([layer_number]),
                salt,
                32,
                **self.SCRYPT_PARAMS
            )

            # Création du chiffreur
            cipher = AES.new(layer_key, AES.MODE_GCM)

            # Chiffrement des données
            ciphertext, tag = cipher.encrypt_and_digest(
                json.dumps(data).encode('utf-8')
            )

            # Construction du résultat
            return {
                'data': base64.b64encode(ciphertext).decode('utf-8'),
                'nonce': base64.b64encode(cipher.nonce).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8'),
                'salt': base64.b64encode(salt).decode('utf-8')
            }

        except Exception as e:
            print(f"Erreur lors du chiffrement de la couche {layer_number}: {e}")
            return None

    def encrypt_private_key(self, private_key, password):
        try:
            # La private_key est déjà au format PEM bytes, pas besoin de l'exporter

            # Génération du sel pour la dérivation de clé
            salt = get_random_bytes(32)

            # Dérivation de la clé
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())

            # Création du cipher AES-GCM
            cipher = AES.new(key, AES.MODE_GCM)

            # Chiffrement de la clé privée PEM
            ciphertext, tag = cipher.encrypt_and_digest(private_key)

            # Création du dictionnaire avec les données encodées en hex
            encrypted_data = {
                'salt': salt.hex(),
                'nonce': cipher.nonce.hex(),
                'tag': tag.hex(),
                'ciphertext': ciphertext.hex()
            }

            return encrypted_data

        except Exception as e:
            print(f"Erreur lors du chiffrement de la clé privée : {e}")
            traceback.print_exc()
            return None

    def decrypt_layer(self, encrypted_data, password, layer_number, salt):
        """Déchiffre une couche spécifique"""
        try:
            # Dérivation de la clé pour cette couche
            layer_key = scrypt(
                password.encode('utf-8') + bytes([layer_number]),
                salt,
                32,
                **self.SCRYPT_PARAMS
            )

            # Création du déchiffreur
            cipher = AES.new(
                layer_key,
                AES.MODE_GCM,
                nonce=base64.b64decode(encrypted_data['nonce'])
            )

            # Déchiffrement et vérification
            decrypted_data = cipher.decrypt_and_verify(
                base64.b64decode(encrypted_data['data']),
                base64.b64decode(encrypted_data['tag'])
            )

            return json.loads(decrypted_data.decode('utf-8'))

        except Exception as e:
            print(f"Erreur lors du déchiffrement de la couche {layer_number}: {e}")
            return None

    def decrypt_private_key(self, encrypted_data, password):
        try:
            # Conversion des données hexadécimales en bytes
            salt = bytes.fromhex(encrypted_data['salt'])
            nonce = bytes.fromhex(encrypted_data['nonce'])
            tag = bytes.fromhex(encrypted_data['tag'])
            ciphertext = bytes.fromhex(encrypted_data['ciphertext'])

            # Dérivation de la clé
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())

            # Création du cipher AES-GCM
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            # Déchiffrement pour obtenir la clé privée PEM
            private_key_pem = cipher.decrypt_and_verify(ciphertext, tag)

            # Import de la clé privée PEM
            return private_key_pem  # Retourne directement le PEM déchiffré

        except Exception as e:
            print(f"Erreur lors du déchiffrement de la clé privée : {e}")
            traceback.print_exc()
            return None

    def encrypt_field_maps(self, field_maps, password):
        """Chiffre toutes les couches"""
        try:
            # Préparation des données à chiffrer
            data_to_encrypt = {
                'layers': {},
                'total_layers': self.NB_LAYERS,
                'version': '1.0'
            }

            # Chiffrement de chaque couche
            for i in range(self.NB_LAYERS):
                print(f"Traitement de la couche {i}...")
                if field_maps[i] is not None:
                    print(f"Données trouvées dans la couche {i}")
                    data_to_encrypt['layers'][str(i)] = field_maps[i]
                    print(f"Couche {i} préparée")

            # Conversion en JSON
            json_data = json.dumps(data_to_encrypt).encode('utf-8')

            # Génération du sel
            salt = get_random_bytes(32)

            # Dérivation de la clé
            key = scrypt(
                password.encode('utf-8'),
                salt,
                32,
                **self.SCRYPT_PARAMS
            )

            # Chiffrement
            cipher = AES.new(key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(json_data)

            # Construction du résultat final
            encrypted_result = {
                'data': base64.b64encode(ciphertext).decode('utf-8'),
                'salt': base64.b64encode(salt).decode('utf-8'),
                'nonce': base64.b64encode(cipher.nonce).decode('utf-8'),
                'tag': base64.b64encode(tag).decode('utf-8')
            }

            return encrypted_result

        except Exception as e:
            print(f"Erreur lors du chiffrement des couches : {e}")
            traceback.print_exc()
            return None

    def decrypt_field_maps(self, encrypted_data, password):
        """Déchiffre le plan des fields"""
        try:
            # Décodage du JSON
            encrypted_package = json.loads(encrypted_data)

            # Vérification de la présence des champs requis
            required_fields = ['data', 'salt', 'nonce', 'tag']
            if not all(field in encrypted_package for field in required_fields):
                raise ValueError("Format de données invalide")

            # Décodage des données base64
            salt = base64.b64decode(encrypted_package['salt'])
            nonce = base64.b64decode(encrypted_package['nonce'])
            tag = base64.b64decode(encrypted_package['tag'])
            ciphertext = base64.b64decode(encrypted_package['data'])

            # Dérivation de la clé
            key = scrypt(
                password.encode('utf-8'),
                salt,
                32,
                **self.SCRYPT_PARAMS
            )

            # Déchiffrement
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

            # Décodage du JSON des données déchiffrées
            decoded_data = json.loads(decrypted_data.decode('utf-8'))

            # Mise à jour des field maps
            self.field_maps = [None] * self.NB_LAYERS
            for layer_id, layer_data in decoded_data['layers'].items():
                self.field_maps[int(layer_id)] = layer_data

            return True

        except Exception as e:
            print(f"Erreur lors du déchiffrement des field maps : {e}")
            traceback.print_exc()
            return False

    def encrypt_file(self, filename, file_password):
        """Chiffre un fichier avec AES"""
        try:
            # Génération d'une clé de session
            session_key = get_random_bytes(32)

            # Chiffrement AES du fichier
            cipher_aes = AES.new(session_key, AES.MODE_GCM)

            with open(filename, 'rb') as file:
                data = file.read()
                ciphertext, tag = cipher_aes.encrypt_and_digest(data)

            # Chiffrement de la clé de session avec RSA
            cipher_rsa = PKCS1_OAEP.new(self.public_key)
            enc_session_key = cipher_rsa.encrypt(session_key)

            # Sauvegarde du fichier chiffré
            encrypted_filename = filename + '.enc'
            with open(encrypted_filename, 'wb') as file:
                [file.write(x) for x in (
                    enc_session_key,
                    cipher_aes.nonce,
                    tag,
                    ciphertext
                )]

            return True

        except Exception as e:
            print(f"Erreur lors du chiffrement du fichier : {e}")
            return False

    def decrypt_file(self, filename, file_password):
        """Déchiffre un fichier"""
        try:
            # Lecture du fichier chiffré
            with open(filename, 'rb') as file:
                enc_session_key = file.read(256)  # Taille de la clé RSA
                nonce = file.read(16)
                tag = file.read(16)
                ciphertext = file.read()

            # Déchiffrement de la clé de session
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            session_key = cipher_rsa.decrypt(enc_session_key)

            # Déchiffrement du fichier
            cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
            data = cipher_aes.decrypt_and_verify(ciphertext, tag)

            # Sauvegarde du fichier déchiffré
            decrypted_filename = filename[:-4]  # Suppression de '.enc'
            with open(decrypted_filename, 'wb') as file:
                file.write(data)

            return True

        except Exception as e:
            print(f"Erreur lors du déchiffrement du fichier : {e}")
            return False

    def init_field_maps(self):
        """Initialise les couches avec des données de test"""
        for i in range(self.NB_LAYERS):
            self.field_maps[i] = {
                'layer_id': i,
                'data': f"Données de test pour la couche {i}"
            }

