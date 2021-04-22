from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import json
import sys
import os

args = sys.argv
F_PATH = ""

def HELP():
    data = """\nDirSec [OPTION] [FUNCTION]\n
    [OPTIONS]:
    \t-D, --dir :- specify Directory
            
    [FUNCTION]:
    \t/path/to/directory :- dirrectory where 'Locker' is present or where you want to create a locker
    """
    print(data)

try:
    if args[1] == "-h" or args[1] == "--help":
        HELP()
        sys.exit()

    elif args[1] == "-D" or args[1] == "--dir":
        F_PATH = f"{args[2].rstrip('/')}/"

    else:
        dat = """\nDirSec [OPTION]\n
    [OPTION] :
        -h , --help :- for help\n"""
        print(dat)
        sys.exit()

except Exception:
    dat = """DirSec [OPTION]\n
[OPTION] :
    -h , --help :- for help\n"""
    print(dat)
    sys.exit()

iv = b'\xc62\xb3\x8d\x94z(\xb2\xbc\x13^\x18\r.\x92\xa7'
backend = default_backend()
key = b''

def padding(data):
        while len(data) % 16 != 0:
            data = data + " "
        return data

def decrypt(inp):
    paa = inp.encode()
    b64 = base64.b64decode(paa)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    dec = decryptor.update(b64) + decryptor.finalize()
    return dec.rstrip().decode()

def encrypt(inp):
    padded_msg = padding(inp).encode()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_msg) + encryptor.finalize()
    b64 = base64.b64encode(ct).decode()
    return b64

# Database Directory Encryption and decryption
def dir_enc(DR):
    DIR = DR
    listFiles = os.listdir(DIR)

    for file in listFiles:
        try:
            if os.path.isfile(f"{DIR}{file}"):
                fl = open(f"{DIR}{file}", "r")
                data = fl.read()
                fl.close()

                ext = file.split(".")[1]

                if data != "":
                    fl = open(f"{DIR}{file.split('.')[0]}.encrypted", "w")
                    fl.write(encrypt(f"EXTENSION:{ext}\n\n{data}"))
                    fl.close()
                    os.remove(f"{DIR}{file}")
                
            elif os.path.isdir(f"{DIR}{file}"):
                dir_enc(f"{DIR}{file}/")
        
        except Exception:
            continue
            

def dir_dec(DR):
    DIR = DR
    listFiles = os.listdir(DIR)

    for file in listFiles:
        try:
            if os.path.isfile(f"{DIR}{file}"):
                if file.split(".")[1] == "encrypted":
                    fl = open(f"{DIR}{file}", "r")
                    data = fl.read()
                    fl.close()

                    dec_data = decrypt(data).split("\n\n")
                    ext = dec_data[0].split(":")[1]

                    fl = open(f"{DIR}{file.split('.')[0]}.{ext}", "w")
                    fl.write(dec_data[1])
                    fl.close
                    os.remove(f"{DIR}{file}")
            
            elif os.path.isdir(f"{DIR}{file}"):
                dir_dec(f"{DIR}{file}/")
        
        except Exception:
            continue

if os.path.exists(f"{F_PATH}Locker"):
    SecFile = open(f"{F_PATH}SecOps.json", "r")
    Data = json.load(SecFile)
    SecFile.close()

    KEY = base64.b64decode(Data['SEC_KEY'].encode())
    key = KEY
    PasHash = Data['PasswordHash']
    State = Data['STATE']
    hashed = hashlib.sha256(input("\n[*] Please Enter your password to continue >> ").encode()).hexdigest()

    if hashed == PasHash:

        if State == "UNSAFE":
            conf = input("[*] Your Data is not safe, press 'y' to encrypt data >> ")

            if conf == "y" or conf == "Y":
                print("\n[SEC] Encrypting Data in the Locker...")
                dir_enc(f"{F_PATH}Locker/")
                
                SecFile = open(f"{F_PATH}SecOps.json", "w")
                Data['STATE'] = "SAFE"
                json.dump(Data, SecFile)
                SecFile.close()

                print("[SEC] Done!")

        if State == "SAFE":
            conf = input("[*] Your Data is safe, press 'y' to decrypt data >> ")

            if conf == "y" or conf == "Y":
                print("\n[SEC] Decrypting Data in the Locker...")
                dir_dec(f"{F_PATH}Locker/")
                
                SecFile = open(f"{F_PATH}SecOps.json", "w")
                Data['STATE'] = "UNSAFE"
                json.dump(Data, SecFile)
                SecFile.close()

                print("[SEC] Done!")

else:
    pas = input("\n[*] Give Me a password for keeping your directory secured >> ")
    STATE = "UNSAFE"
    KEY = base64.b64encode(os.urandom(32)).decode()
    hashed = hashlib.sha256(pas.encode()).hexdigest()

    SecFile = open(f"{F_PATH}SecOps.json", "w")
    dic = {"PasswordHash":hashed, "SEC_KEY":KEY, "STATE":"UNSAFE"}
    json.dump(dic, SecFile)
    SecFile.close()

    os.mkdir("Locker")
