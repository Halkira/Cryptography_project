import json
from Crypto.Random import get_random_bytes
import getpass
import sys
import RSA
import AES
import traceback

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
            # Premier mot de passe pour la clé RSA
            key_password = getpass.getpass("Entrez un mot de passe pour la clé privée RSA : ")
            # Second mot de passe pour le fichier
            file_password = getpass.getpass("Entrez un mot de passe pour le fichier : ")

            key_manager = RSA.KeyManager()
            if not key_manager.generate_keys(key_password, file_password):
                print("Erreur lors de la génération des clés RSA")
                continue
            print("\nClés RSA générées")

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
                message = input("Entrez le message à chiffrer : ")
                if algo_choix == "1":
                    with open("public_key.pem", "rb") as f:
                        public_key = f.read()
                    encrypted = RSA.encrypt_rsa(message, public_key)
                else:
                    encrypted = AES.encrypt_aes(message, aes_key)

                if encrypted is None:
                    print("Erreur de chiffrement. Veuillez réessayer.\n")
                else:
                    print(f"\nMessage chiffré : {encrypted}\n")


            elif choix == "2":

                encrypted_message = input("Entrez le message chiffré : ")
                if algo_choix == "1":

                    try:
                        # Mot de passe du fichier d'abord
                        file_password = getpass.getpass("Entrez le mot de passe du fichier : ")
                        # Déchiffrement du fichier
                        decrypted_data = key_manager.decrypt_file("private_key.enc", file_password)

                        if decrypted_data:
                            # Puis mot de passe de la clé
                            key_password = getpass.getpass("Entrez le mot de passe de la clé privée : ")
                            # Déchiffrement de la clé privée
                            private_key = key_manager.decrypt_private_key(key_password, json.dumps(decrypted_data))

                            if private_key:
                                # Utilisation directe de la clé privée pour le déchiffrement
                                decrypted = RSA.decrypt_rsa(encrypted_message, private_key)

                                if decrypted:
                                    print(f"\nMessage déchiffré : {decrypted}\n")
                                else:
                                    print("Erreur lors du déchiffrement du message")
                            else:
                                print("Erreur lors du déchiffrement de la clé privée")
                        else:
                            print("Erreur lors du déchiffrement du fichier")
                    except Exception as e:
                        print(f"Erreur lors du déchiffrement : {e}")
                        traceback.print_exc()


if __name__ == "__main__":
    main()