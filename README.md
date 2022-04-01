# Directory-Security
##Deprecated##
A python program to keep your files safe and secured
# DirSec

### Windows
python DirSec.py --dir "path/to/directory"
### Linux
python3 DirSec.py --dir "path/to/directory"
## Key-Points
after --dir give the path to the directory where you want to create a directory called 'Locker' for storing your files
* After running the program for the first time it will take a root password to authorise one user and will create a 'SecOps.json' file for storing some config.
* If the json file is deleted or removed and your folder is already encrypted say goodbye to all the files, as it is AES 256bit encrypted and without that file its impossible to decrypt the data back
* Now Encrypt or Decrypt [Program will decide that, depending on if the folder is encrypted or decrypted] Enjoy!

## Disclaimer
I won't be responsible if you are unable to decrypt the data back, so USE IT AT YOUR OWN RISK.

# SecMan
This program is used for updating your password

### Windows
python DirMan.py --dir "path/to/directory/and/SecOps.json/file"
### Linux
python3 DirMan.py --dir "path/to/directory/and/SecOps.json/file"

* First give your current password and then you will be able to update your password
