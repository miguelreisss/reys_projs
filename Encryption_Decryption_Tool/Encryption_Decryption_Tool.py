from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os, base64, getpass, sys

# AES Encryption and Decryption
def aes_encrypt(plaintext, password):
    # Generate a random 16-byte salt
    salt = os.urandom(16)
    
    # Derive a 32-byte key from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Generate a random 16-byte initialization vector (IV)
    iv = os.urandom(16)

    # Pad the plaintext to be a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()

    # Encrypt the padded plaintext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Combine salt, IV, and ciphertext into one message
    encrypted_message = salt + iv + ciphertext
    return base64.b64encode(encrypted_message).decode()

def aes_decrypt(encrypted_message, password):
    # Decode the base64-encoded encrypted message
    encrypted_message_bytes = base64.b64decode(encrypted_message)

    # Extract the salt, IV, and ciphertext
    salt = encrypted_message_bytes[:16]
    iv = encrypted_message_bytes[16:32]
    ciphertext = encrypted_message_bytes[32:]

    # Derive the key from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())

    # Decrypt the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()

# RSA Key Generation
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# RSA Encryption and Decryption
def rsa_encrypt(plaintext, public_key):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

def rsa_decrypt(encrypted_message, private_key):
    encrypted_message_bytes = base64.b64decode(encrypted_message)
    plaintext = private_key.decrypt(
        encrypted_message_bytes,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Back to menu
def back_to_menu():
    back = input("Do you want to be back to menu? (yes/no): ")
    if back == "yes":
        try:
            menu()
        except Exception as e:
            print(f"Failed to load menu: {e}")
    elif back == "no":
        try:
            sys.exit()
        except Exception as e:
            print(f"Failed to close the programm: {e}")
    else:
        print("Invalid choice.")
        try:
            back_to_menu()
        except Exception as e:
            print(f"Failed to load if you want to be back to menu: {e}")

# User Interface
def menu():
    print("1. AES Encryption")
    print("2. AES Decryption")
    print("3. RSA Encryption")
    print("4. RSA Decryption")
    print("5. Generate RSA Key Pair")
    print("6. Close Programm")

    choice = input("Enter your choice (1-6): ")

    if choice == '1':
        plaintext = input("Enter the text to encrypt: ")
        password = getpass.getpass("Enter the password: ")
        encrypted_message = aes_encrypt(plaintext, password)
        print(f"Encrypted message: {encrypted_message}")

    elif choice == '2':
        encrypted_message = input("Enter the text to decrypt: ")
        password = getpass.getpass("Enter the password: ")
        try:
            decrypted_message = aes_decrypt(encrypted_message, password)
            print(f"Decrypted message: {decrypted_message}")
        except Exception as e:
            print(f"Decryption failed: {e}")

    elif choice == '3':
        plaintext = input("Enter the text to encrypt: ")
        public_keys = input("Enter the RSA public key: ")
        try:
            encrypted_message = rsa_encrypt(plaintext, public_key)
            print(f"Encrypted message: {encrypted_message}")
        except Exception as e:
            print(f"RSA encryption failed: {e}")

    elif choice == '4':
        encrypted_message = input("Enter the text to decrypt: ")
        private_key_path = input("Enter the RSA private key: ")
        try:
            decrypted_message = rsa_decrypt(encrypted_message, private_key)
            print(f"Decrypted message: {decrypted_message}")
        except Exception as e:
            print(f"RSA decryption failed: {e}")

    elif choice == '5':
        try:
            private_key, public_key = generate_rsa_keys()
            print("RSA key pair generated\n")
            print(f"Public RSA Key: {public_key}")
            print(f"Private RSA Key: {private_key}")
        except Exception as e:
            print(f"Key generation failed: {e}")

    elif choice == '6':
        try:
            sys.exit()
        except Exception as e:
            print(f"Failed to close the programm: {e}")

    else:
        print("Invalid choice.")
    
    try:
        back_to_menu()
    except Exception as e:
        print(f"Failed to load if you want to be back to menu: {e}")

if __name__ == "__main__":
    menu()