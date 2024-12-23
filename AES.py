from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os


class AESCipher:
    def __init__(self):
        self.block_size = AES.block_size

    def validate_path(self, path):
        """Vérifie si le chemin est valide et accessible"""
        try:
            # Convertir en chemin absolu
            abs_path = os.path.abspath(path)
            # Vérifier si le chemin existe
            if not os.path.exists(os.path.dirname(abs_path)):
                print(f"Le répertoire {os.path.dirname(abs_path)} n'existe pas.")
                return None
            return abs_path
        except Exception as e:
            print(f"Erreur lors de la validation du chemin: {str(e)}")
            return None

    def encrypt_file(self, filepath, key):
        try:
            # Valider le chemin d'entrée
            abs_path = self.validate_path(filepath)
            if not abs_path:
                return False

            # Vérifier si le fichier existe
            if not os.path.isfile(abs_path):
                print(f"Le fichier {abs_path} n'existe pas.")
                return False

            # Lire le fichier
            with open(abs_path, 'rb') as f:
                data = f.read()

            # Chiffrer les données
            cipher = AES.new(key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data, self.block_size))
            iv = base64.b64encode(cipher.iv).decode('utf-8')
            ct = base64.b64encode(ct_bytes).decode('utf-8')
            encrypted_data = iv + ":" + ct

            # Créer le chemin de sortie
            output_path = abs_path + ".enc"

            # Écrire le fichier chiffré
            with open(output_path, 'w') as f:
                f.write(encrypted_data)

            print(f"Fichier chiffré sauvegardé : {output_path}")
            return True

        except Exception as e:
            print(f"Erreur lors du chiffrement du fichier: {str(e)}")
            return False

    def decrypt_file(self, filepath, key):
        try:
            # Valider le chemin d'entrée
            abs_path = self.validate_path(filepath)
            if not abs_path:
                return False

            # Vérifier si le fichier existe
            if not os.path.isfile(abs_path):
                print(f"Le fichier {abs_path} n'existe pas.")
                return False

            # Lire le fichier chiffré
            with open(abs_path, 'r') as f:
                encrypted_data = f.read()

            # Déchiffrer les données
            iv, ct = encrypted_data.split(':')
            iv = base64.b64decode(iv)
            ct = base64.b64decode(ct)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), self.block_size)

            # Créer le chemin de sortie
            if abs_path.endswith('.enc'):
                output_path = abs_path[:-4]
            else:
                output_path = abs_path + '.dec'

            # Écrire le fichier déchiffré
            with open(output_path, 'wb') as f:
                f.write(pt)

            print(f"Fichier déchiffré sauvegardé : {output_path}")
            return True

        except Exception as e:
            print(f"Erreur lors du déchiffrement du fichier: {str(e)}")
            return False
