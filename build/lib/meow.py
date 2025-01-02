#!/usr/bin/env python3

from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
import base64

# Caesar Cipher Functions
def caesar_encrypt(plaintext, shift):
    encrypted = ""
    for char in plaintext:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            encrypted += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted += char
    return encrypted

def caesar_decrypt(ciphertext, shift):
    decrypted = ""
    for char in ciphertext:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            decrypted += chr((ord(char) - shift_base - shift) % 26 + shift_base)
        else:
            decrypted += char
    return decrypted

# AES Functions
def aes_encrypt(plaintext, key, iv):
    key = base64.b64decode(key)
    iv = base64.b64decode(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return base64.b64encode(ciphertext).decode('utf-8')

def aes_decrypt(ciphertext, key, iv):
    ciphertext = base64.b64decode(ciphertext)
    key = base64.b64decode(key)
    iv = base64.b64decode(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

# DES Functions
def des_encrypt(plaintext, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), DES.block_size))
    return base64.b64encode(ciphertext).decode('utf-8')

def des_decrypt(ciphertext, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(base64.b64decode(ciphertext)), DES.block_size)
    return plaintext.decode('utf-8')

# Vigenère Cipher Functions
def vigenere_encrypt(plaintext, key):
    encrypted = ""
    key = key.lower()
    key_index = 0
    for char in plaintext:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('a')
            encrypted += chr((ord(char) - shift_base + shift) % 26 + shift_base)
            key_index += 1
        else:
            encrypted += char
    return encrypted

def vigenere_decrypt(ciphertext, key):
    decrypted = ""
    key = key.lower()
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_index % len(key)]) - ord('a')
            decrypted += chr((ord(char) - shift_base - shift) % 26 + shift_base)
            key_index += 1
        else:
            decrypted += char
    return decrypted

# RSA Functions
def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key):
    public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def rsa_decrypt(ciphertext, private_key):
    private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(private_key)
    plaintext = cipher.decrypt(base64.b64decode(ciphertext))
    return plaintext.decode('utf-8')

def print_welcome_message():
    welcome_art = """
     __    __  ___    ______   ____   _       __     _ 
   _/_/   /  |/  /   / ____/  / __ \ | |     / /    | |
 _/_/    / /|_/ /   / __/    / / / / | | /| / /     / /
< <     / /  / /   / /___   / /_/ /  | |/ |/ /     _>_>
/ /    /_/  /_/   /_____/   \____/   |__/|__/    _/_/  
\_\                                             /_/    

        ▗▖ ▗▖▗▄▄▄▖▗▖    ▗▄▄▖ ▗▄▖ ▗▖  ▗▖▗▄▄▄▖
        ▐▌ ▐▌▐▌   ▐▌   ▐▌   ▐▌ ▐▌▐▛▚▞▜▌▐▌   
        ▐▌ ▐▌▐▛▀▀▘▐▌   ▐▌   ▐▌ ▐▌▐▌  ▐▌▐▛▀▀▘
        ▐▙█▟▌▐▙▄▄▖▐▙▄▄▖▝▚▄▄▖▝▚▄▞▘▐▌  ▐▌▐▙▄▄▖
        
        
Meow is a tool for encrypting and decrypting texts
Use it wisely and don't forget to follow @abacuscybernity

by:  https://github.com/thahtanagara
    """
    print(welcome_art)

# Main Menu
def main():
    print_welcome_message()
    print("============= Encryption and Decryption Tool =============")
    print("1. Caesar Cipher")
    print("2. AES (CBC)")
    print("3. DES")
    print("4. Vigenère Cipher")
    print("5. RSA")
    choice = input("Choose an option (1-5): ")

    if choice == "1":
        print("\n=== Caesar Cipher ===")
        print("1. Encrypt")
        print("2. Decrypt")
        caesar_choice = input("Choose an option (1/2): ")

        if caesar_choice == "1":
            plaintext = input("Enter the plaintext: ")
            shift = int(input("Enter the shift key (0-25): "))
            print("Encrypted text:", caesar_encrypt(plaintext, shift))
        elif caesar_choice == "2":
            ciphertext = input("Enter the ciphertext: ")
            shift = int(input("Enter the shift key (0-25): "))
            print("Decrypted text:", caesar_decrypt(ciphertext, shift))

    elif choice == "2":
        print("\n=== AES (CBC) ===")
        print("1. Encrypt")
        print("2. Decrypt")
        aes_choice = input("Choose an option (1/2): ")

        if aes_choice == "1":
            plaintext = input("Enter the plaintext: ")
            key = input("Enter the Base64-encoded key (16/24/32 bytes): ")
            iv = input("Enter the Base64-encoded IV (16 bytes): ")
            print("Encrypted text:", aes_encrypt(plaintext, key, iv))
        elif aes_choice == "2":
            ciphertext = input("Enter the Base64-encoded ciphertext: ")
            key = input("Enter the Base64-encoded key (16/24/32 bytes): ")
            iv = input("Enter the Base64-encoded IV (16 bytes): ")
            print("Decrypted text:", aes_decrypt(ciphertext, key, iv))

    elif choice == "3":
        print("\n=== DES ===")
        print("1. Encrypt")
        print("2. Decrypt")
        des_choice = input("Choose an option (1/2): ")

        if des_choice == "1":
            plaintext = input("Enter the plaintext: ")
            key = input("Enter the 8-character key: ")
            print("Encrypted text:", des_encrypt(plaintext, key))
        elif des_choice == "2":
            ciphertext = input("Enter the Base64-encoded ciphertext: ")
            key = input("Enter the 8-character key: ")
            print("Decrypted text:", des_decrypt(ciphertext, key))

    elif choice == "4":
        print("\n=== Vigenère Cipher ===")
        print("1. Encrypt")
        print("2. Decrypt")
        vigenere_choice = input("Choose an option (1/2): ")

        if vigenere_choice == "1":
            plaintext = input("Enter the plaintext: ")
            key = input("Enter the key: ")
            print("Encrypted text:", vigenere_encrypt(plaintext, key))
        elif vigenere_choice == "2":
            ciphertext = input("Enter the ciphertext: ")
            key = input("Enter the key: ")
            print("Decrypted text:", vigenere_decrypt(ciphertext, key))

    elif choice == "5":
        print("\n=== RSA ===")
        print("1. Generate Keys")
        print("2. Encrypt")
        print("3. Decrypt")
        rsa_choice = input("Choose an option (1/2/3): ")

        if rsa_choice == "1":
            private_key, public_key = rsa_generate_keys()
            print("Private Key:")
            print(private_key.decode('utf-8'))
            print("\nPublic Key:")
            print(public_key.decode('utf-8'))
        elif rsa_choice == "2":
            plaintext = input("Enter the plaintext: ")
            public_key = input("Enter the public key: ")
            print("Encrypted text:", rsa_encrypt(plaintext, public_key))
        elif rsa_choice == "3":
            ciphertext = input("Enter the Base64-encoded ciphertext: ")
            private_key = input("Enter the private key: ")
            print("Decrypted text:", rsa_decrypt(ciphertext, private_key))

    else:
        print("Invalid option.")
    
    print("MeowCrypto Tool is running...")

if __name__ == "__main__":
    main()
