import hashlib
import json
import sys

args = sys.argv
F_PATH = ""

def HELP():
    data = """\nDirMan [OPTION] [FUNCTION]\n
    [OPTIONS]:
    \t-D, --dir :- specify Directory
            
    [FUNCTION]:
    \t/path/to/directory :- dirrectory where 'SecOps.json' file is present
    """
    print(data)

try:
    if args[1] == "-h" or args[1] == "--help":
        HELP()
        sys.exit()

    elif args[1] == "-D" or args[1] == "--dir":
        F_PATH = f"{args[2].rstrip('/')}/"

    else:
        dat = """\nDirMan [OPTION]\n
    [OPTION] :
        -h , --help :- for help\n"""
        print(dat)
        sys.exit()

except Exception:
    dat = """DirMan [OPTION]\n
[OPTION] :
    -h , --help :- for help\n"""
    print(dat)
    sys.exit()

fl = open(f"{F_PATH}SecOps.json", "r")
Data = json.load(fl)
fl.close()

hashed = hashlib.sha256(input("\n[*] Please Enter your password to continue >> ").encode()).hexdigest()

if Data["PasswordHash"] == hashed:
    conf = input("Are you sure you want to update your Password? (y/n) >> ")
    if conf == "y" or conf == "Y":
        newHash = hashlib.sha256(input("\n[*] Enter new Password >> ").encode()).hexdigest()
        SecFile = open(f"{F_PATH}SecOps.json", "w")
        Data['PasswordHash'] = newHash
        json.dump(Data, SecFile)
        SecFile.close()
        print("Password Updated!")

    else:
        print("Your Password remains the same")