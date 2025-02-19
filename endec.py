import os
import re
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# Constants
SALT_SIZE = 16  # 16 bytes for PBKDF2 salt
NONCE_SIZE = 12  # 12 bytes for AES-GCM nonce
TAG_SIZE = 16  # 16 bytes for AES-GCM authentication tag
KEY_SIZE = 32  # 32 bytes = 256-bit AES key
ITERATIONS = 100000  # PBKDF2 iterations
MAX_TRIES = 5  # Maximum password attempts

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a cryptographic key from a password using PBKDF2."""
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=ITERATIONS, hmac_hash_module=SHA256)

def generate_encrypted_filename(input_file: str) -> str:
    """Generates an encrypted filename by replacing the last '.' with '_' and appending '.enc'."""
    return re.sub(r'\.(?=[^.]+$)', '_', input_file) + ".enc"

def generate_decrypted_filename(input_file: str) -> str:
    """Restores the original filename by replacing the last '_' before '.enc' with a '.'."""
    return re.sub(r'_(?=[^.]+\.enc$)', '.', input_file)[:-4]  # Remove .enc extension

def clean_filename(filename: str) -> str:
    """Removes unnecessary quotes from filenames caused by drag-and-drop."""
    filename = filename.strip("'")
    return filename.strip('"')

def encrypt_file(input_file: str, password: str):
    """Encrypts a file using AES-256-GCM with a password."""
    input_file = clean_filename(input_file)
    output_file = generate_encrypted_filename(input_file)
    salt = get_random_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(NONCE_SIZE))
    
    with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
        f_out.write(salt)
        f_out.write(cipher.nonce)
        
        while chunk := f_in.read(4096):
            ciphertext = cipher.encrypt(chunk)
            f_out.write(ciphertext)
        
        f_out.write(cipher.digest())  # Write authentication tag for integrity verification
    
    os.remove(input_file)  # Delete original file after encryption

def decrypt_file(input_file: str):
    """Attempts to decrypt a file up to MAX_TRIES times before failing."""
    input_file = clean_filename(input_file)
    output_file = generate_decrypted_filename(input_file)
    
    for attempt in range(MAX_TRIES):
        password = input("Password: ")
        try:
            with open(input_file, 'rb') as f_in:
                salt = f_in.read(SALT_SIZE)
                nonce = f_in.read(NONCE_SIZE)
                key = derive_key(password, salt)
                
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                
                with open(output_file, 'wb') as f_out:
                    file_size = os.path.getsize(input_file)
                    data_size = file_size - (SALT_SIZE + NONCE_SIZE + TAG_SIZE)
                    
                    while data_size > 0:
                        chunk = f_in.read(min(4096, data_size))
                        data_size -= len(chunk)
                        f_out.write(cipher.decrypt(chunk))
                    
                    tag = f_in.read(TAG_SIZE)
                    cipher.verify(tag)  # Verify integrity
            os.remove(input_file)  # Delete encrypted file after successful decryption
            print("Decryption successful!")
            return
        except ValueError:
            print(f"Wrong Password! Attempts left: {MAX_TRIES - attempt - 1}")
            if os.path.exists(output_file):
                os.remove(output_file)  # Remove incorrectly decrypted file
    
    print("Maximum attempts reached. Decryption failed.")

print("Endec encrypt/decrypt files: \n")
filename = input("Filename: ")
filename = clean_filename(filename)

if filename.endswith(".enc"):
    decrypt_file(filename)
else: 
    password = input("Password: ")
    encrypt_file(filename, password)
