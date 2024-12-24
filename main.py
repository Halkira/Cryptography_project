import json
from Crypto.Random import get_random_bytes
import getpass
import sys
import RSA
import AES
import traceback
from Crypto.PublicKey import RSA as CryptoRSA
import os

def handle_rsa_new_keys():
    """Gestion de la génération de nouvelles clés RSA"""
    try:
        # Demande des mots de passe
        key_password = getpass.getpass("Entrez un mot de passe pour la clé privée RSA : ")
        field_maps_password = getpass.getpass("Entrez un mot de passe pour les field maps : ")
        file_password = getpass.getpass("Entrez un mot de passe pour le fichier : ")

        # Initialisation du gestionnaire de clés
        key_manager = RSA.KeyManager()
        key_manager.init_field_maps()

        # Génération et test des clés
        private_key, public_key = key_manager.test_key_generation_and_decryption(key_password)
        if not private_key or not public_key:
            print("\nÉchec des tests, arrêt du programme")
            return None

        # Stockage de la clé publique
        key_manager.public_key = CryptoRSA.import_key(public_key)

        # Chiffrement de la clé privée
        encrypted_private_key = key_manager.encrypt_private_key(private_key, key_password)
        if not encrypted_private_key:
            print("Erreur lors du chiffrement de la clé privée")
            return None

        # Chiffrement des field maps
        encrypted_maps = key_manager.encrypt_field_maps(key_manager.field_maps, field_maps_password)
        if not encrypted_maps:
            print("Erreur lors du chiffrement des field maps")
            return None

        # Sauvegarde des fichiers
        with open('public_key.pem', 'wb') as f:
            f.write(public_key)
        with open('private_key.enc', 'w') as f:
            json.dump(encrypted_private_key, f)
        with open('field_maps.enc', 'w') as f:
            json.dump(encrypted_maps, f)

        print("\nClés RSA générées et sauvegardées")
        return key_manager, file_password

    except Exception as e:
        print(f"Erreur lors de la génération des clés : {str(e)}")
        traceback.print_exc()
        return None


def handle_rsa_operations():
    """Gestion des opérations RSA avec clés existantes"""
    key_manager = RSA.KeyManager()
    while True:
        print("\nMenu RSA :")
        print("1. Chiffrer")
        print("2. Déchiffrer")
        print("3. Retour au menu principal")
        print("4. Quitter")
        choix = input("Votre choix : ")

        if choix == "3":
            break
        elif choix == "4":
            print("\nAu revoir !")
            sys.exit()
        elif choix == "1":  # Chiffrement
            try:
                filename = input("Entrez le nom du fichier à chiffrer : ")
                # Charger la clé publique
                with open('public_key.pem', 'rb') as f:
                    public_key = f.read()
                key_manager.public_key = CryptoRSA.import_key(public_key)

                file_password = getpass.getpass("Entrez un mot de passe pour le fichier : ")
                if key_manager.encrypt_file(filename, file_password):
                    print(f"\nFichier chiffré avec succès : {filename}.enc")
                else:
                    print("Erreur lors du chiffrement du fichier")
            except Exception as e:
                print(f"Erreur lors du chiffrement : {str(e)}")
                traceback.print_exc()

        elif choix == "2":  # Déchiffrement
            try:
                filename = input("Entrez le nom du fichier chiffré : ")

                # Déchiffrement des field maps
                with open('field_maps.enc', 'r') as f:
                    encrypted_maps = json.load(f)

                field_maps_password = getpass.getpass("Entrez le mot de passe des field maps : ")
                if not key_manager.decrypt_field_maps(encrypted_maps, field_maps_password):
                    print("Erreur lors du déchiffrement des field maps")
                    continue

                # Déchiffrement de la clé privée
                with open('private_key.enc', 'r') as f:
                    encrypted_private_key = json.load(f)

                key_password = getpass.getpass("Entrez le mot de passe de la clé privée : ")
                decrypted_private_key = key_manager.decrypt_private_key(encrypted_private_key, key_password)

                if decrypted_private_key:
                    key_manager.private_key = CryptoRSA.import_key(decrypted_private_key)
                else:
                    print("Erreur lors du déchiffrement de la clé privée")
                    continue

                # Déchiffrement du fichier
                file_password = getpass.getpass("Entrez le mot de passe du fichier : ")
                if key_manager.decrypt_file(filename, file_password):
                    print(f"\nFichier déchiffré avec succès : {filename[:-4]}")
                else:
                    print("Erreur lors du déchiffrement du fichier")

            except Exception as e:
                print(f"Erreur lors du déchiffrement : {str(e)}")
                traceback.print_exc()

def handle_aes_operations():
    """Gestion des opérations AES"""
    aes_manager = AES.AESCipher()

    while True:
        print("\nMenu AES :")
        print("1. Chiffrer un fichier")
        print("2. Déchiffrer un fichier")
        print("3. Retour au menu principal")
        print("4. Quitter")
        choix = input("Votre choix : ")

        if choix == "3":
            break
        elif choix == "4":
            print("\nAu revoir !")
            sys.exit()
        elif choix == "1":  # Chiffrement
            try:
                filepath = input("Entrez le chemin du fichier à chiffrer : ")
                password = getpass.getpass("Entrez le mot de passe pour le chiffrement : ")
                if aes_manager.encrypt_file(filepath, password):
                    print("Chiffrement terminé avec succès")
                else:
                    print("Échec du chiffrement")
            except Exception as e:
                print(f"Erreur : {str(e)}")
                traceback.print_exc()

        elif choix == "2":  # Déchiffrement
            try:
                filepath = input("Entrez le chemin du fichier à déchiffrer : ")
                password = getpass.getpass("Entrez le mot de passe pour le déchiffrement : ")
                if aes_manager.decrypt_file(filepath, password):
                    print("Déchiffrement terminé avec succès")
                else:
                    print("Échec du déchiffrement")
            except Exception as e:
                print(f"Erreur : {str(e)}")
                traceback.print_exc()


def main():
    while True:
        print("\nChoisissez l'algorithme de chiffrement :")
        print("1. RSA - Générer nouvelles clés")
        print("2. RSA - Utiliser clés existantes")
        print("3. RSA")
        print("4. AES")
        print("5. Quitter")
        algo_choix = input("Votre choix : ")

        if algo_choix == "5":
            print("Au revoir !")
            break

        if algo_choix == "1":
            result = handle_rsa_new_keys()
            if result:
                key_manager, file_password = result
                # Continuer avec les opérations de chiffrement/déchiffrement si nécessaire

        elif algo_choix == "2":
            key_manager = RSA.KeyManager()  # Création de l'instance
            key_manager.decrypt_with_existing_keys()

        elif algo_choix == "3":
            handle_rsa_operations()

        elif algo_choix == "4":
            handle_aes_operations()

        else:
            print("Choix invalide. Veuillez réessayer.\n")


def handle_rsa_operations():
    """Gestion des opérations RSA avec clés existantes"""
    key_manager = RSA.KeyManager()
    while True:
        print("\nMenu RSA :")
        print("1. Chiffrer")
        print("2. Déchiffrer")
        print("3. Retour au menu principal")
        print("4. Quitter")
        choix = input("Votre choix : ")

        if choix == "3":
            break
        elif choix == "4":
            print("\nAu revoir !")
            sys.exit()
        elif choix == "1":  # Chiffrement
            try:
                filepath = input("Entrez le chemin complet du fichier à chiffrer : ")
                if not os.path.exists(filepath):
                    print(f"Erreur : Le fichier {filepath} n'existe pas.")
                    continue

                keys_dir = input("Entrez le répertoire contenant les clés : ")
                base_name = input("Entrez le nom de base des fichiers de clés : ")

                public_key_path = os.path.join(keys_dir, f"{base_name}_public.pem")

                if not os.path.exists(public_key_path):
                    print(f"Erreur : Le fichier de clé publique {public_key_path} n'existe pas.")
                    continue

                with open(public_key_path, 'rb') as f:
                    public_key = f.read()
                key_manager.public_key = CryptoRSA.import_key(public_key)

                file_password = getpass.getpass("Entrez un mot de passe pour le fichier : ")
                if key_manager.encrypt_file(filepath, file_password):
                    print(f"\nFichier chiffré avec succès : {filepath}.enc")
                else:
                    print("Erreur lors du chiffrement du fichier")

            except Exception as e:
                print(f"Erreur lors du chiffrement : {str(e)}")
                traceback.print_exc()

        elif choix == "2":  # Déchiffrement
            try:
                encrypted_filepath = input("Entrez le chemin complet du fichier chiffré : ")
                if not os.path.exists(encrypted_filepath):
                    print(f"Erreur : Le fichier {encrypted_filepath} n'existe pas.")
                    continue

                keys_dir = input("Entrez le répertoire contenant les clés : ")
                base_name = input("Entrez le nom de base des fichiers de clés : ")

                private_key_path = os.path.join(keys_dir, f"{base_name}_private.enc")
                field_maps_path = os.path.join(keys_dir, f"{base_name}_field_maps.enc")

                if not os.path.exists(private_key_path):
                    print(f"Erreur : Le fichier de clé privée {private_key_path} n'existe pas.")
                    continue
                if not os.path.exists(field_maps_path):
                    print(f"Erreur : Le fichier field maps {field_maps_path} n'existe pas.")
                    continue

                with open(field_maps_path, 'r') as f:
                    encrypted_maps = json.load(f)

                field_maps_password = getpass.getpass("Entrez le mot de passe des field maps : ")
                if not key_manager.decrypt_field_maps(encrypted_maps, field_maps_password):
                    print("Erreur lors du déchiffrement des field maps")
                    continue

                with open(private_key_path, 'rb') as f:
                    private_key_data = f.read()

                key_password = getpass.getpass("Entrez le mot de passe de la clé privée : ")
                # Utiliser CryptoRSA au lieu de RSA
                key_manager.private_key = CryptoRSA.import_key(private_key_data, passphrase=key_password)

                file_password = getpass.getpass("Entrez le mot de passe du fichier : ")
                success, decrypted_data = key_manager.decrypt_file(encrypted_filepath, file_password)

                if success:
                    # Créer le nom du fichier de sortie
                    output_path = encrypted_filepath[:-4] if encrypted_filepath.endswith(
                        '.enc') else encrypted_filepath + '.dec'
                    # Écrire les données déchiffrées dans un nouveau fichier
                    with open(output_path, 'wb') as f:
                        f.write(decrypted_data)
                    print(f"\nFichier déchiffré avec succès : {output_path}")
                else:
                    print("Erreur lors du déchiffrement du fichier")

            except Exception as e:
                print(f"Erreur lors du déchiffrement : {str(e)}")
                traceback.print_exc()


if __name__ == "__main__":
    main()
