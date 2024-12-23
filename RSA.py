import getpass
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import json
from Crypto.Protocol.KDF import scrypt
import traceback


class KeyManager:
    def __init__(self):
        self.SCRYPT_PARAMS = {
            'N': 2 ** 14,
            'r': 8,
            'p': 1
        }
        self.NB_LAYERS = 50
        self.field_maps = [None] * self.NB_LAYERS
        self.private_key = None  # Ajouté
        self.public_key = None  # Ajouté

        self.NB_LAYERS = 50  # Ajout de cette ligne
        self.field_maps = [None] * self.NB_LAYERS  # Utilisation de NB_LAYERS ici

    def generate_key_pair(self, key_password):
        """Génère une nouvelle paire de clés RSA et les field maps"""
        try:
            # Génération de la paire de clés RSA
            key = RSA.generate(4096)

            # Export de la clé privée avec mot de passe
            private_key = key.export_key(passphrase=key_password)
            public_key = key.publickey().export_key()

            # Demander le répertoire de destination
            save_dir = input("Entrez le répertoire où sauvegarder les clés : ")
            base_name = input("Entrez le nom de base pour les fichiers de clés : ")

            # Créer le répertoire s'il n'existe pas
            if not os.path.exists(save_dir):
                os.makedirs(save_dir)

            # Définir les chemins des fichiers
            private_key_path = os.path.join(save_dir, f"{base_name}_private.enc")
            public_key_path = os.path.join(save_dir, f"{base_name}_public.pem")
            field_maps_path = os.path.join(save_dir, f"{base_name}_field_maps.enc")

            # Initialiser les field maps
            self.init_field_maps()

            # Demander le mot de passe pour les field maps
            field_maps_password = getpass.getpass("Entrez un mot de passe pour les field maps : ")

            # Chiffrer et sauvegarder les field maps
            encrypted_maps = self.encrypt_field_maps(self.field_maps, field_maps_password)
            if encrypted_maps:
                with open(field_maps_path, 'w') as f:
                    json.dump(encrypted_maps, f)

            # Sauvegarder la clé privée (déjà chiffrée par export_key)
            with open(private_key_path, 'wb') as f:
                f.write(private_key)

            # Sauvegarder la clé publique
            with open(public_key_path, 'wb') as f:
                f.write(public_key)

            print(f"\nFichiers sauvegardés avec succès:")
            print(f"Clé privée: {private_key_path}")
            print(f"Clé publique: {public_key_path}")
            print(f"Field maps: {field_maps_path}")

            return private_key, public_key

        except Exception as e:
            print(f"Erreur lors de la génération des clés : {e}")
            traceback.print_exc()
            return None, None

    def encrypt_private_key(self, private_key, password):
        try:
            # La private_key est déjà au format PEM bytes, pas besoin de l'exporter

            # Génération du sel pour la dérivation de clé
            salt = get_random_bytes(32)

            # Dérivation de la clé avec scrypt
            key = scrypt(
                password.encode('utf-8'),
                salt,
                32,
                **self.SCRYPT_PARAMS
            )

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
            # Vérification de la structure des données
            required_fields = ['salt', 'nonce', 'tag', 'ciphertext']
            for field in required_fields:
                if field not in encrypted_data:
                    print(f"Erreur : champ '{field}' manquant dans les données chiffrées")
                    return None

            # Debug : afficher la structure des données (sans les valeurs sensibles)
            print("Structure des données chiffrées :")
            print(f"Longueur salt : {len(encrypted_data['salt'])} caractères")
            print(f"Longueur nonce : {len(encrypted_data['nonce'])} caractères")
            print(f"Longueur tag : {len(encrypted_data['tag'])} caractères")
            print(f"Longueur ciphertext : {len(encrypted_data['ciphertext'])} caractères")

            try:
                # Conversion des données hex en bytes
                salt = bytes.fromhex(encrypted_data['salt'])
                nonce = bytes.fromhex(encrypted_data['nonce'])
                tag = bytes.fromhex(encrypted_data['tag'])
                ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
            except ValueError as e:
                print(f"Erreur lors de la conversion des données hexadécimales : {e}")
                return None

            # Debug : afficher les tailles des données converties
            print("\nTailles après conversion en bytes :")
            print(f"Salt : {len(salt)} bytes")
            print(f"Nonce : {len(nonce)} bytes")
            print(f"Tag : {len(tag)} bytes")
            print(f"Ciphertext : {len(ciphertext)} bytes")

            # Dérivation de la clé
            key = scrypt(
                password.encode('utf-8'),
                salt,
                32,
                **self.SCRYPT_PARAMS
            )

            # Création du cipher AES-GCM
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            try:
                # Déchiffrement de la clé privée
                private_key_data = cipher.decrypt_and_verify(ciphertext, tag)

                # Vérification que les données déchiffrées ressemblent à une clé PEM
                if b'-----BEGIN' not in private_key_data or b'-----END' not in private_key_data:
                    print("Les données déchiffrées ne semblent pas être une clé PEM valide")
                    return None

                return private_key_data

            except ValueError as e:
                print(f"Erreur lors de la vérification MAC : {e}")
                print("Le mot de passe est probablement incorrect")
                return None

        except Exception as e:
            print(f"Erreur lors du déchiffrement de la clé privée : {e}")
            traceback.print_exc()
            return None

    def encrypt_field_maps(self, field_maps, password):
        try:
            # Préparation des données à chiffrer
            data_to_encrypt = {
                'layers': {},
                'total_layers': self.NB_LAYERS,
                'version': '1.0'
            }

            # Chiffrement de chaque couche
            for i in range(self.NB_LAYERS):
                if field_maps[i] is not None:
                    data_to_encrypt['layers'][str(i)] = field_maps[i]

            # Conversion en JSON puis en bytes
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
                'ciphertext': ciphertext.hex(),  # Changé de 'data' à 'ciphertext'
                'salt': salt.hex(),
                'nonce': cipher.nonce.hex(),
                'tag': tag.hex()
            }

            return encrypted_result

        except Exception as e:
            print(f"Erreur lors du chiffrement des couches : {e}")
            traceback.print_exc()
            return None

    def decrypt_field_maps(self, encrypted_data, password):
        try:
            # Si encrypted_data est en bytes, le convertir en JSON
            if isinstance(encrypted_data, bytes):
                encrypted_data = json.loads(encrypted_data.decode('utf-8'))

            # Vérification de la structure des données
            required_fields = ['salt', 'nonce', 'tag', 'ciphertext']
            for field in required_fields:
                if field not in encrypted_data:
                    print(f"Erreur : champ '{field}' manquant dans les field maps")
                    return False

            # Conversion des données hex en bytes
            salt = bytes.fromhex(encrypted_data['salt'])
            nonce = bytes.fromhex(encrypted_data['nonce'])
            tag = bytes.fromhex(encrypted_data['tag'])
            ciphertext = bytes.fromhex(encrypted_data['ciphertext'])

            # Dérivation de la clé
            key = scrypt(
                password.encode('utf-8'),
                salt,
                32,
                **self.SCRYPT_PARAMS
            )

            # Création du cipher AES-GCM
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            try:
                # Déchiffrement des field maps
                decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
                self.field_maps = json.loads(decrypted_data.decode('utf-8'))
                return True
            except ValueError as e:
                print(f"Erreur lors de la vérification MAC des field maps : {e}")
                return False

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

            return True, data

        except Exception as e:
            print(f"Erreur lors du déchiffrement du fichier : {e}")
            return False, None

    def init_field_maps(self):
        """Initialise les couches avec des données de test"""
        for i in range(self.NB_LAYERS):
            self.field_maps[i] = {
                'layer_id': i,
                'data': f"Données de test pour la couche {i}"
            }

    def load_existing_keys(self, private_key_path, public_key_path, field_maps_path, key_password, field_password):
        try:
            # Charger la clé publique
            with open(public_key_path, 'rb') as f:
                self.public_key = RSA.import_key(f.read())

            # Charger et déchiffrer la clé privée
            with open(private_key_path, 'rb') as f:
                encrypted_private_key_data = json.load(f)
                decrypted_private_key = self.decrypt_private_key(encrypted_private_key_data, key_password)
                if decrypted_private_key is None:
                    print("Échec du déchiffrement de la clé privée")
                    return False
                self.private_key = RSA.import_key(decrypted_private_key, passphrase=key_password)

            # Charger et déchiffrer les field maps
            with open(field_maps_path, 'rb') as f:
                encrypted_field_maps_data = json.load(f)
                if not self.decrypt_field_maps(encrypted_field_maps_data, field_password):
                    print("Échec du déchiffrement des field maps")
                    return False

            return True

        except Exception as e:
            print(f"Erreur lors du chargement des clés : {str(e)}")
            traceback.print_exc()
            return False

    @staticmethod
    def decrypt_with_existing_keys():
        try:
            # Demander les chemins des fichiers
            private_key_path = input("Chemin du fichier de clé privée (.enc) : ")
            public_key_path = input("Chemin du fichier de clé publique (.pem) : ")
            field_maps_path = input("Chemin du fichier field maps (.enc) : ")
            encrypted_file_path = input("Chemin du fichier à déchiffrer : ")

            # Vérifier l'existence des fichiers
            for path in [private_key_path, public_key_path, field_maps_path, encrypted_file_path]:
                if not os.path.exists(path):
                    print(f"Le fichier {path} n'existe pas.")
                    return

            # Demander les deux mots de passe
            key_password = getpass.getpass("Entrez le mot de passe de la clé privée : ")
            field_password = getpass.getpass("Entrez le mot de passe des field maps : ")

            # Initialiser le gestionnaire de clés
            key_manager = KeyManager()

            # Charger les clés existantes
            if not key_manager.load_existing_keys(
                    private_key_path,
                    public_key_path,
                    field_maps_path,
                    key_password,
                    field_password
            ):
                print("Échec du chargement des clés")
                return

            # Déchiffrer le fichier
            success, decrypted_data = key_manager.decrypt_file(encrypted_file_path, key_password)

            if success and decrypted_data is not None:
                # Créer le nom du fichier de sortie
                output_path = encrypted_file_path.replace('.enc', '') if encrypted_file_path.endswith(
                    '.enc') else encrypted_file_path + '.dec'

                # Écrire le fichier déchiffré
                try:
                    with open(output_path, 'wb') as f:
                        f.write(decrypted_data)
                    print(f"\nFichier déchiffré et sauvegardé avec succès : {output_path}")
                except Exception as e:
                    print(f"Erreur lors de l'écriture du fichier : {e}")
            else:
                print("Échec du déchiffrement du fichier")

        except Exception as e:
            print(f"Erreur lors du déchiffrement : {str(e)}")
            traceback.print_exc()

    def save_keys(self, private_key, public_key, field_maps, key_password, field_password):
        """
        Sauvegarde les clés et field maps dans des fichiers
        """
        try:
            # Demander le répertoire de destination
            save_dir = input("Entrez le répertoire où sauvegarder les clés : ")
            base_name = input("Entrez le nom de base pour les fichiers de clés : ")

            # Créer le répertoire s'il n'existe pas
            if not os.path.exists(save_dir):
                os.makedirs(save_dir)

            # Définir les chemins des fichiers
            private_key_path = os.path.join(save_dir, f"{base_name}_private.enc")
            public_key_path = os.path.join(save_dir, f"{base_name}_public.pem")
            field_maps_path = os.path.join(save_dir, f"{base_name}_field_maps.enc")

            # Chiffrer la clé privée
            encrypted_private_key = self.encrypt_private_key(private_key, key_password)
            if encrypted_private_key is None:
                return False

            # Chiffrer les field maps
            encrypted_field_maps = self.encrypt_field_maps(field_maps, field_password)
            if encrypted_field_maps is None:
                return False

            # Sauvegarder la clé privée chiffrée
            with open(private_key_path, 'w') as f:
                json.dump(encrypted_private_key, f)

            # Sauvegarder la clé publique
            with open(public_key_path, 'wb') as f:
                f.write(public_key)

            # Sauvegarder les field maps chiffrés
            with open(field_maps_path, 'w') as f:
                json.dump(encrypted_field_maps, f)

            print(f"\nClés sauvegardées avec succès:")
            print(f"Clé privée: {private_key_path}")
            print(f"Clé publique: {public_key_path}")
            print(f"Field maps: {field_maps_path}")

            return True

        except Exception as e:
            print(f"Erreur lors de la sauvegarde des clés : {str(e)}")
            traceback.print_exc()
            return False

    def test_key_generation_and_decryption(self, key_password):
        """Test la génération et le déchiffrement des clés"""
        print("\n=== Test de génération et déchiffrement des clés ===\n")

        # 1. Génération des clés
        print(f"1. Génération des clés avec le mot de passe fourni")
        private_key, public_key = self.generate_key_pair(key_password)

        if not private_key or not public_key:
            return None, None

        # 2. Chiffrement de la clé privée
        encrypted_private_key = self.encrypt_private_key(private_key, key_password)
        if not encrypted_private_key:
            return None, None

        print("2. Chiffrement de la clé privée")
        print("Structure de la clé privée chiffrée:")
        print(json.dumps(encrypted_private_key, indent=2))

        # 3. Test de déchiffrement immédiat
        print("\n3. Test de déchiffrement immédiat")
        # Vérification des tailles
        print("Structure des données chiffrées :")
        print(f"Longueur salt : {len(encrypted_private_key['salt'])} caractères")
        print(f"Longueur nonce : {len(encrypted_private_key['nonce'])} caractères")
        print(f"Longueur tag : {len(encrypted_private_key['tag'])} caractères")
        print(f"Longueur ciphertext : {len(encrypted_private_key['ciphertext'])} caractères")

        # 4. Vérification finale
        decrypted_key = self.decrypt_private_key(encrypted_private_key, key_password)
        if decrypted_key == private_key:
            print("\n4. Vérification de l'intégrité")
            print("Succès : La clé déchiffrée correspond à l'originale")
            return private_key, public_key
        else:
            print("Échec : La clé déchiffrée ne correspond pas à l'originale")
            return None, None

