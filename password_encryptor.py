from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from getpass import getpass
import sys
import os

def encrypt_message(passphrase, message):
    salt = get_random_bytes(16)
    key = scrypt(passphrase, salt, key_len=32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    return salt + cipher.iv + ciphertext

def decrypt_message(passphrase, encrypted_data):
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    key = scrypt(passphrase, salt, key_len=32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
    return decrypted_message

def encryptData():
    passphrase = getpass("Your password: ")
    message = input("Your message: ")
    encrypted_data = encrypt_message(passphrase, message)
    with open("encryptedPassword.bin", "wb") as encryptedPassword:
        encryptedPassword.write(encrypted_data)
    print("Encrypted data:", encrypted_data)

def decryptData():
    try:
        with open("encryptedPassword.bin", "rb") as encryptedPassword:
            encrypted_data = encryptedPassword.read()
        passphrase = getpass("Enter your password: ")
        decrypted_message = decrypt_message(passphrase, encrypted_data)
        print("Decrypted message:", decrypted_message)
    except FileNotFoundError:
        print("No encrypted data found.")
    except Exception as e:
        print("Decryption failed:", e)

def main():
    answer = input("1- Encrypt message\n2- Decrypt message\n3- Remove stored message\n4- Exit\n\nEnter a number: ")

    if answer == "1":
        encryptData()
    elif answer == "2":
        decryptData()
    elif answer == "3":
        if os.path.exists("encryptedPassword.bin"):
            os.remove("encryptedPassword.bin")
            print('Removed "encryptedPassword.bin"')
        else:
            print('Could not find file "encryptedPassword.bin"')
    elif answer == "4":
        sys.exit()
    else:
        print("Enter a valid number.")

if __name__ == "__main__":
    main()