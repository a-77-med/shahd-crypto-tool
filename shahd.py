#!/usr/bin/python3

import rsa
import base64
import os
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import zipfile
import datetime
from Crypto.Cipher import DES
import hashlib
import hmac

# ======================================
# ASCII Animated Banner
# ======================================
logo = r"""
 ____  _           _   _   ____  
/ ___|| |__   __ _| | | | |  _ \
\___ \| '_ \ / _` | | | | | | | |
 ___) | | | | (_| | | | | | |_| |
|____/|_| |_|\__,_|_| |_| |____/

      [ AHMED Hamada RSA Encryption ]

     ░█▀▀█ ─█▀▀█ ─█▀▀█ ░█─░█ █▀▀▄
     ░█─── ░█▄▄█ ░█▀▀█ ░█─░█ █──█
     ░█▄▄█ ░█─░█ ░█▄▄█ ─▀▄▄▀ █▄▄▀

"""

def type_write(text, delay=0.004):
    for char in text:
        print(char, end="", flush=True)
        time.sleep(delay)
    print("\n")

def clear_screen():
    os.system("clear")

# ======================================
# LOGGER
# ======================================
LOG_FILE = "shahd_log.txt"
def log(action, message=""):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{datetime.datetime.now()}] {action} {message}\n")

# ======================================
# RSA FUNCTIONS
# ======================================
def generate_rsa_keys(key_size=2048):
    public_key, private_key = rsa.newkeys(key_size)
    with open("public.pem", "wb") as pub:
        pub.write(public_key.save_pkcs1())
    with open("private.pem", "wb") as priv:
        priv.write(private_key.save_pkcs1())
    return public_key, private_key

def rsa_encrypt(message, public_key):
    return base64.b64encode(rsa.encrypt(message.encode(), public_key)).decode('utf-8')

def rsa_decrypt(encrypted_b64, private_key):
    encrypted_bytes = base64.b64decode(encrypted_b64)
    return rsa.decrypt(encrypted_bytes, private_key).decode('utf-8')

def rsa_sign(message, private_key):
    signature = rsa.sign(message.encode(), private_key, 'SHA-256')
    return base64.b64encode(signature).decode('utf-8')

def rsa_verify(message, signature_b64, public_key):
    signature = base64.b64decode(signature_b64)
    try:
        rsa.verify(message.encode(), signature, public_key)
        return True
    except rsa.VerificationError:
        return False

# ======================================
# AES FUNCTIONS
# ======================================
def pad(data):
    padding = AES.block_size - len(data) % AES.block_size
    return data + bytes([padding]*padding)

def unpad(data):
    return data[:-data[-1]]

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode()))
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

def aes_decrypt(enc_b64, key):
    enc = base64.b64decode(enc_b64)
    iv = enc[:16]
    ct = enc[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct)).decode('utf-8')

# ======================================
# DES FUNCTIONS
# ======================================
def des_pad(data):
    padding = 8 - len(data) % 8
    return data + bytes([padding] * padding)

def des_unpad(data):
    return data[:-data[-1]]

def des_encrypt(message, key):
    # DES key must be exactly 8 bytes
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes!")
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(des_pad(message.encode()))
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

def des_decrypt(enc_b64, key):
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes!")
    enc = base64.b64decode(enc_b64)
    iv = enc[:8]
    ct = enc[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return des_unpad(cipher.decrypt(ct)).decode('utf-8')

# ======================================
# HYBRID FUNCTIONS (RSA + AES)
# ======================================
def hybrid_encrypt(message, public_key):
    aes_key = get_random_bytes(16)
    enc_message = aes_encrypt(message, aes_key)
    enc_key = base64.b64encode(rsa.encrypt(aes_key, public_key)).decode('utf-8')
    return enc_key, enc_message

def hybrid_decrypt(enc_key_b64, enc_message, private_key):
    aes_key = rsa.decrypt(base64.b64decode(enc_key_b64), private_key)
    return aes_decrypt(enc_message, aes_key)

# ======================================
# PACKER / UNPACKER
# ======================================
def pack_file(file_path, zip_name="archive.zip"):
    with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(file_path, os.path.basename(file_path))
    return zip_name

def unpack_file(zip_name, extract_to="."):
    with zipfile.ZipFile(zip_name, 'r') as zipf:
        zipf.extractall(extract_to)
    return extract_to

# ======= Hashing & HMAC ======
def list_hash_algorithms():
    algs = sorted(hashlib.algorithms_available)
    return algs

def compute_hash_text(alg, text, shake_length=None):
    alg = alg.lower()
    if alg.startswith("shake"):
        if not shake_length:
            raise ValueError("SHAKE requires output length (in bytes).")
        h = hashlib.new(alg)
        h.update(text.encode('utf-8'))
        return h.hexdigest(shake_length)
    else:
        h = hashlib.new(alg)
        h.update(text.encode('utf-8'))
        return h.hexdigest()

def compute_hash_file(alg, filepath, chunk_size=8192, shake_length=None):
    alg = alg.lower()
    if alg.startswith("shake"):
        if not shake_length:
            raise ValueError("SHAKE requires output length (in bytes).")
        h = hashlib.new(alg)
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest(shake_length)
    else:
        h = hashlib.new(alg)
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

def compute_hmac_text(alg, key, text, shake_length=None):
    alg = alg.lower()
    if not alg.startswith("shake"):
        if isinstance(key, str):
            key = key.encode()
        hm = hmac.new(key, msg=text.encode('utf-8'), digestmod=alg)
        return hm.hexdigest()
    else:
        # Simplified HMAC for SHAKE - استخدام تنفيذ مبسط
        if isinstance(key, str):
            key = key.encode()
        combined = key + text.encode()
        h = hashlib.new(alg)
        h.update(combined)
        return h.hexdigest(shake_length) if shake_length else h.hexdigest()

def compute_hmac_file(alg, key, filepath, chunk_size=8192, shake_length=None):
    alg = alg.lower()
    if not alg.startswith("shake"):
        if isinstance(key, str):
            key = key.encode()
        hm = hmac.new(key, digestmod=alg)
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hm.update(chunk)
        return hm.hexdigest()
    else:
        # Simplified for SHAKE
        if isinstance(key, str):
            key = key.encode()
        h = hashlib.new(alg)
        h.update(key)
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest(shake_length) if shake_length else h.hexdigest()

# ====== Helper UI functions ======
def ui_list_algorithms():
    algs = list_hash_algorithms()
    print("\nAvailable algorithms:\n")
    for i, alg in enumerate(algs, 1):
        print(f"{i:2d}. {alg}")
    input("\nPress Enter to return...")

def ui_hash_text():
    clear_screen()
    print("=== Hash Text ===\n")
    alg = input("Algorithm (e.g. sha256, sha3_512, blake2b, shake_128): ").strip()
    if alg.lower().startswith("shake"):
        try:
            length = int(input("Output length in bytes (e.g. 32): ").strip())
        except:
            print("Invalid length")
            input("Enter to return...")
            return
    else:
        length = None
    text = input("Enter text to hash: ")
    try:
        digest = compute_hash_text(alg, text, shake_length=length)
        print(f"\n[{alg}] Digest: {digest}")
    except Exception as e:
        print("Error:", e)
    input("\nPress Enter to return...")

def ui_hash_file():
    clear_screen()
    print("=== Hash File ===\n")
    alg = input("Algorithm: ").strip()
    if alg.lower().startswith("shake"):
        try:
            length = int(input("Output length in bytes (e.g. 32): ").strip())
        except:
            print("Invalid length")
            input("Enter to return...")
            return
    else:
        length = None
    path = input("File path: ").strip()
    if not os.path.isfile(path):
        print("File not found!")
        input("Enter to return...")
        return
    try:
        digest = compute_hash_file(alg, path, shake_length=length)
        print(f"\n[{alg}] File digest: {digest}")
    except Exception as e:
        print("Error:", e)
    input("\nPress Enter to return...")

def ui_hmac_text():
    clear_screen()
    print("=== HMAC Text ===\n")
    alg = input("Algorithm (e.g. sha256, sha1): ").strip()
    key = input("HMAC key: ").strip()
    if alg.lower().startswith("shake"):
        try:
            length = int(input("Output length in bytes (e.g. 32): ").strip())
        except:
            print("Invalid length")
            input("Enter to return...")
            return
    else:
        length = None
    text = input("Text to HMAC: ")
    try:
        tag = compute_hmac_text(alg, key, text, shake_length=length)
        print(f"\nHMAC [{alg}]: {tag}")
    except Exception as e:
        print("Error:", e)
    input("\nPress Enter to return...")

def ui_hmac_file():
    clear_screen()
    print("=== HMAC File ===\n")
    alg = input("Algorithm: ").strip()
    key = input("HMAC key: ").strip()
    path = input("File path: ").strip()
    if not os.path.isfile(path):
        print("File not found!")
        input("Enter to return...")
        return
    if alg.lower().startswith("shake"):
        try:
            length = int(input("Output length in bytes (e.g. 32): ").strip())
        except:
            print("Invalid length")
            input("Enter to return...")
            return
    else:
        length = None
    try:
        tag = compute_hmac_file(alg, key, path, shake_length=length)
        print(f"\nHMAC [{alg}] File tag: {tag}")
    except Exception as e:
        print("Error:", e)
    input("\nPress Enter to return...")

# ======================================
# MAIN MENU - CORRECTED VERSION
# ======================================
def menu():
    while True:
        clear_screen()
        type_write(logo, 0.002)
        print("""
[1] Generate RSA Keys
[2] Encrypt Message (RSA)
[3] Decrypt Message (RSA)
[4] Sign Message
[5] Verify Signature
[6] AES Encrypt
[7] AES Decrypt
[8] Hybrid Encrypt (RSA + AES)
[9] Hybrid Decrypt
[10] Pack File
[11] Unpack File
[12] DES Encrypt
[13] DES Decrypt
[14] List Hash Algorithms
[15] Hash Text
[16] Hash File
[17] HMAC Text
[18] HMAC File
[19] Exit

""")
        choice = input("Select: ")

        if choice == "1":
            clear_screen()
            generate_rsa_keys()
            print("[✓] RSA Keys Generated!")
            log("RSA Keys Generated")
            input("\nPress Enter to return...")
        
        elif choice == "2":
            clear_screen()
            try:
                with open("public.pem","rb") as f:
                    pub = rsa.PublicKey.load_pkcs1(f.read())
                msg = input("Enter message: ")
                enc = rsa_encrypt(msg, pub)
                print("\nEncrypted:", enc)
                log("RSA Encrypted Message", msg)
            except Exception as e:
                print("Error:", e)
            input("\nPress Enter to return...")
        
        elif choice == "3":
            clear_screen()
            try:
                with open("private.pem","rb") as f:
                    priv = rsa.PrivateKey.load_pkcs1(f.read())
                enc = input("Paste encrypted Base64: ")
                dec = rsa_decrypt(enc, priv)
                print("\nDecrypted:", dec)
                log("RSA Decrypted Message", dec)
            except Exception as e:
                print("Error:", e)
            input("\nPress Enter to return...")
        
        elif choice == "4":
            clear_screen()
            try:
                with open("private.pem","rb") as f:
                    priv = rsa.PrivateKey.load_pkcs1(f.read())
                msg = input("Message to sign: ")
                sig = rsa_sign(msg, priv)
                print("\nSignature (Base64):", sig)
                log("RSA Signed Message", msg)
            except Exception as e:
                print("Error:", e)
            input("\nPress Enter to return...")
        
        elif choice == "5":
            clear_screen()
            try:
                with open("public.pem","rb") as f:
                    pub = rsa.PublicKey.load_pkcs1(f.read())
                msg = input("Message: ")
                sig = input("Signature (Base64): ")
                if rsa_verify(msg, sig, pub):
                    print("\n[✓] Signature is VALID!")
                    log("RSA Signature Verified", msg)
                else:
                    print("\n[✗] Signature INVALID!")
            except Exception as e:
                print("Error:", e)
            input("\nPress Enter to return...")
        
        elif choice == "6":
            clear_screen()
            msg = input("Enter message to AES encrypt: ")
            key = input("Enter 16-byte key: ").encode()
            enc = aes_encrypt(msg, key)
            print("\nEncrypted:", enc)
            log("AES Encrypted", msg)
            input("\nPress Enter to return...")
        
        elif choice == "7":
            clear_screen()
            enc = input("Paste AES encrypted Base64: ")
            key = input("Enter 16-byte key: ").encode()
            dec = aes_decrypt(enc, key)
            print("\nDecrypted:", dec)
            log("AES Decrypted", dec)
            input("\nPress Enter to return...")
        
        elif choice == "8":
            clear_screen()
            try:
                with open("public.pem","rb") as f:
                    pub = rsa.PublicKey.load_pkcs1(f.read())
                msg = input("Message to hybrid encrypt: ")
                enc_key, enc_msg = hybrid_encrypt(msg, pub)
                print("\nEncrypted AES Key (RSA):", enc_key)
                print("Encrypted Message (AES):", enc_msg)
                log("Hybrid Encrypted", msg)
            except Exception as e:
                print("Error:", e)
            input("\nPress Enter to return...")
        
        elif choice == "9":
            clear_screen()
            try:
                with open("private.pem","rb") as f:
                    priv = rsa.PrivateKey.load_pkcs1(f.read())
                enc_key = input("Encrypted AES key (RSA Base64): ")
                enc_msg = input("Encrypted message (AES Base64): ")
                dec = hybrid_decrypt(enc_key, enc_msg, priv)
                print("\nDecrypted:", dec)
                log("Hybrid Decrypted", dec)
            except Exception as e:
                print("Error:", e)
            input("\nPress Enter to return...")
        
        elif choice == "10":
            clear_screen()
            file_path = input("File to pack: ")
            zip_name = input("Zip name (default archive.zip): ") or "archive.zip"
            pack_file(file_path, zip_name)
            print("\nPacked to", zip_name)
            log("Packed File", file_path)
            input("\nPress Enter to return...")
        
        elif choice == "11":
            clear_screen()
            zip_name = input("Zip to unpack: ")
            extract_to = input("Extract to (default current dir): ") or "."
            unpack_file(zip_name, extract_to)
            print("\nUnpacked to", extract_to)
            log("Unpacked File", zip_name)
            input("\nPress Enter to return...")
        
        elif choice == "12":
            clear_screen()
            msg = input("Enter message to DES encrypt: ")
            key = input("Enter 8-byte DES key: ").encode()
            try:
                enc = des_encrypt(msg, key)
                print("\nDES Encrypted:", enc)
                log("DES Encrypted Message", msg)
            except Exception as e:
                print("Error:", e)
            input("\nPress Enter to return...")

        elif choice == "13":
            clear_screen()
            enc = input("Paste DES encrypted Base64: ")
            key = input("Enter 8-byte DES key: ").encode()
            try:
                dec = des_decrypt(enc, key)
                print("\nDES Decrypted:", dec)
                log("DES Decrypted Message", dec)
            except Exception as e:
                print("Error:", e)
            input("\nPress Enter to return...")
        
        elif choice == "14":
            ui_list_algorithms()
        
        elif choice == "15":
            ui_hash_text()
        
        elif choice == "16":
            ui_hash_file()
        
        elif choice == "17":
            ui_hmac_text()
        
        elif choice == "18":
            ui_hmac_file()
        
        elif choice == "19":
            clear_screen()
            print("Exiting ShahD_RSA ULTRA PRO...")
            break
        
        else:
            input("Invalid choice! Press Enter...")

if __name__ == "__main__":
    menu()
