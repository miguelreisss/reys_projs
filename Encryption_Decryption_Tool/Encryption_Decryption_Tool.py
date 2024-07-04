from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import getpass

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

# Save RSA keys to files
def save_rsa_keys(private_key, public_key, private_key_path, public_key_path):
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(private_key_path, 'wb') as private_file:
        private_file.write(pem_private_key)
    
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(public_key_path, 'wb') as public_file:
        public_file.write(pem_public_key)

# Load RSA keys from files
def load_rsa_private_key(private_key_path):
    with open(private_key_path, 'rb') as private_file:
        pem_private_key = private_file.read()
        private_key = serialization.load_pem_private_key(
            pem_private_key,
            password=None,
            backend=default_backend()
        )
    return private_key

def load_rsa_public_key(public_key_path):
    with open(public_key_path, 'rb') as public_file:
        pem_public_key = public_file.read()
        public_key = serialization.load_pem_public_key(
            pem_public_key,
            backend=default_backend()
        )
    return public_key

# User Interface
def main():
    print("Encryption/Decryption Tool")
    print("Choose an option:")
    print("1. AES Encryption")
    print("2. AES Decryption")
    print("3. RSA Encryption")
    print("4. RSA Decryption")
    print("5. Generate RSA Key Pair")

    choice = input("Enter your choice (1-5): ")

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
        public_key_path = input("Enter the path to the RSA public key file: ")
        try:
            public_key = load_rsa_public_key(public_key_path)
            encrypted_message = rsa_encrypt(plaintext, public_key)
            print(f"Encrypted message: {encrypted_message}")
        except Exception as e:
            print(f"RSA encryption failed: {e}")

    elif choice == '4':
        encrypted_message = input("Enter the text to decrypt: ")
        private_key_path = input("Enter the path to the RSA private key file: ")
        try:
            private_key = load_rsa_private_key(private_key_path)
            decrypted_message = rsa_decrypt(encrypted_message, private_key)
            print(f"Decrypted message: {decrypted_message}")
        except Exception as e:
            print(f"RSA decryption failed: {e}")

    elif choice == '5':
        private_key_path = input("Enter the path to save the RSA private key: ")
        public_key_path = input("Enter the path to save the RSA public key: ")
        try:
            private_key, public_key = generate_rsa_keys()
            save_rsa_keys(private_key, public_key, private_key_path, public_key_path)
            print(f"RSA key pair generated and saved to {private_key_path} and {public_key_path}")
        except Exception as e:
            print(f"Key generation failed: {e}")

    else:
        print("Invalid choice. Please run the program again.")

if __name__ == "__main__":
    main()
