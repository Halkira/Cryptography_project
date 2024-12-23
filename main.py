import json
from Crypto.Random import get_random_bytes
import getpass
import sys
import RSA
import AES
import traceback
from Crypto.PublicKey import RSA as CryptoRSA


def main():
        while True:
            # Choix de l'algorithme
            print("\nChoisissez l'algorithme de chiffrement :")
            print("1. RSA")
            print("2. AES")
            print("3. Quitter")
            algo_choix = input("Votre choix : ")

            if algo_choix == "3":
                print("Au revoir !")
                break

            if algo_choix not in ["1", "2"]:
                print("Choix invalide. Veuillez réessayer.\n")
                continue

            # Initialisation des clés selon l'algorithme choisi
            if algo_choix == "1":
                # Mots de passe pour RSA
                key_password = getpass.getpass("Entrez un mot de passe pour la clé privée RSA : ")
                field_maps_password = getpass.getpass("Entrez un mot de passe pour les field maps : ")
                file_password = getpass.getpass("Entrez un mot de passe pour le fichier : ")

                key_manager = RSA.KeyManager()
                key_manager.init_field_maps()
                # Génération des clés
                private_key, public_key = key_manager.generate_key_pair(key_password)
                if not private_key or not public_key:
                    print("Erreur lors de la génération des clés RSA")
                    continue

                # Stockage de la clé publique dans l'instance
                key_manager.public_key = CryptoRSA.import_key(public_key)

                # Chiffrement de la clé privée
                encrypted_private_key = key_manager.encrypt_private_key(private_key, key_password)
                if not encrypted_private_key:
                    print("Erreur lors du chiffrement de la clé privée")
                    continue

                # Chiffrement des field maps
                encrypted_maps = key_manager.encrypt_field_maps(key_manager.field_maps, field_maps_password)
                if not encrypted_maps:
                    print("Erreur lors du chiffrement des field maps")
                    continue


                # Modifiez la partie de sauvegarde des fichiers comme suit :
                try:
                    with open('public_key.pem', 'wb') as f:
                        f.write(public_key)

                    with open('private_key.enc', 'w') as f:
                        json.dump(encrypted_private_key, f)

                    # Pour la sauvegarde :
                    with open('field_maps.enc', 'w') as f:
                        json.dump(encrypted_maps, f)

                    # Pour la lecture :
                    with open('field_maps.enc', 'r') as f:
                        encrypted_maps_data = json.load(f)

                    print("\nClés RSA générées et sauvegardées")

                except Exception as e:
                    print(f"Erreur lors de la sauvegarde des fichiers : {str(e)}")
                    traceback.print_exc()  # Ajout pour voir l'erreur complète
                    continue


            else:
                aes_key = get_random_bytes(32)
                print("\nClé AES générée")

            while True:
                # Menu des opérations
                print("\nQue souhaitez-vous faire ?")
                print("1. Chiffrer")
                print("2. Déchiffrer")
                print("3. Retour au choix de l'algorithme")
                print("4. Quitter")
                choix = input("Votre choix : ")

                if choix == "3":
                    break
                if choix == "4":
                    print("\nAu revoir !")
                    sys.exit()

                if choix == "1":
                    filename = input("Entrez le nom du fichier à chiffrer : ")
                    if algo_choix == "1":
                        try:
                            if key_manager.encrypt_file(filename, file_password):
                                print(f"\nFichier chiffré avec succès : {filename}.enc")
                            else:
                                print("Erreur lors du chiffrement du fichier")
                        except Exception as e:
                            print(f"Erreur lors du chiffrement du fichier : {e}")


                elif choix == "2":

                    filename = input("Entrez le nom du fichier chiffré : ")

                    if algo_choix == "1":

                        try:

                            # Déchiffrement des field maps

                            with open('field_maps.enc', 'rb') as f:

                                encrypted_maps_data = f.read()

                            field_maps_password = getpass.getpass("Entrez le mot de passe des field maps : ")

                            if not key_manager.decrypt_field_maps(encrypted_maps_data, field_maps_password):
                                print("Erreur lors du déchiffrement des field maps")

                                continue

                            # Déchiffrement de la clé privée

                            with open('private_key.enc', 'r') as f:

                                encrypted_private_key_data = json.load(f)

                            # Vérification de la structure des données

                            if not isinstance(encrypted_private_key_data, dict):
                                print("Format de clé privée invalide")

                                continue

                            required_fields = ['salt', 'nonce', 'tag', 'ciphertext']

                            if not all(field in encrypted_private_key_data for field in required_fields):
                                print("Structure de la clé privée incorrecte")

                                continue

                            key_password = getpass.getpass("Entrez le mot de passe de la clé privée : ")

                            decrypted_private_key = key_manager.decrypt_private_key(
                                encrypted_private_key_data,
                                key_password
                            )

                            if decrypted_private_key:
                                try:
                                    key_manager.private_key = CryptoRSA.import_key(decrypted_private_key,
                                                                                   passphrase=key_password)
                                except Exception as e:
                                    print(f"Erreur lors de l'import de la clé privée : {e}")
                                    continue
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

                            print(f"Erreur lors du déchiffrement : {e}")

                            traceback.print_exc()


if __name__ == "__main__":
    main()
