from PyQt5.QtWidgets import QMainWindow, QFileDialog, QMessageBox, QLineEdit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PyQt5 import QtCore, QtGui, QtWidgets
import hashlib
import base64
import json
import os

class Store:
    DIR_MAIN = ""
    iv = b''
    key = b''
    
class ShowDialog():
    def ShwSuc(self, data):
        msgBox = QMessageBox()
        msgBox.setFixedSize(400, 400)
        msgBox.setIcon(QMessageBox.Information)
        msgBox.setText(data)
        msgBox.setWindowTitle("SUCCESS")
    
        returnValue = msgBox.exec_()
        if returnValue == QMessageBox.Ok:
            pass

    def ShwError(self, data):
        msgBox = QMessageBox()
        msgBox.setFixedSize(400, 400)
        msgBox.setIcon(QMessageBox.Critical)
        msgBox.setText(data)
        msgBox.setWindowTitle("ERROR")
    
        returnValue = msgBox.exec_()
        if returnValue == QMessageBox.Ok:
            pass

class Ui_main(QMainWindow):
    def __init__(self):
        super(Ui_main, self).__init__()

        self.setFixedSize(750, 280)
        self.mainLabel = QtWidgets.QLabel(self)
        self.mainLabel.setGeometry(QtCore.QRect(250, 20, 261, 41))
        self.mainLabel.setObjectName("mainLabel")
        self.btnManager = QtWidgets.QPushButton(self)
        self.btnManager.setGeometry(QtCore.QRect(150, 180, 181, 61))
        self.btnManager.setStyleSheet("color: rgb(255, 255, 255);\n"
"background-color: rgb(0, 170, 0);\n"
"border-radius: 15px;")
        self.btnManager.setObjectName("btnManager")
        self.btGuard = QtWidgets.QPushButton(self)
        self.btGuard.setGeometry(QtCore.QRect(420, 180, 181, 61))
        self.btGuard.setStyleSheet("color: rgb(255, 255, 255);\n"
"background-color: rgb(0, 170, 0);\n"
"border-radius: 15px;")
        self.btGuard.setObjectName("btGuard")
        self.btGuard.clicked.connect(self.backend)

        self.btnManager.clicked.connect(self.PassManRedirect)

        self.dirLabel = QtWidgets.QLabel(self)
        self.dirLabel.setGeometry(QtCore.QRect(90, 97, 91, 31))
        self.dirLabel.setObjectName("dirLabel")

        self.dirEdit = QtWidgets.QLineEdit(self)
        self.dirEdit.setGeometry(QtCore.QRect(190, 100, 350, 27))
        self.dirEdit.setStyleSheet("background-color: rgb(62, 62, 62);\n"
"color: rgb(255, 255, 255);\n"
"font: 12pt \"Cantarell\";\n"
"border-radius: 10px;")
        self.dirEdit.setObjectName("dirEdit")
        self.findBtn = QtWidgets.QPushButton(self)
        self.findBtn.setGeometry(QtCore.QRect(560, 97, 91, 31))
        self.findBtn.setStyleSheet("color: rgb(255, 255, 255);\n"
"background-color: rgb(0, 170, 0);\n"
"border-radius: 15px;")
        self.findBtn.setObjectName("findBtn")
        self.findBtn.clicked.connect(self.find)

        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("main", "Directory Guard"))
        self.mainLabel.setText(_translate("main", "<html><head/><body><p align=\"center\"><span style=\" font-size:24pt; text-decoration: underline;\">Directory Guard</span></p></body></html>"))
        self.btnManager.setText(_translate("main", "Password Manager"))
        self.btGuard.setText(_translate("main", "Guard"))
        self.dirLabel.setText(_translate("EncryptLocker", "<html><head/><body><p align=\"center\"><span style=\" font-size:14pt;\">Directory</span></p></body></html>"))
        self.findBtn.setText(_translate("EncryptLocker", "Find"))

        self.show()
    
    def find(self):
        dialog = QFileDialog(self)
        fname = dialog.getExistingDirectory(self)
        self.dirEdit.setText(fname)
        Store.DIR_MAIN = f"{fname.rstrip('/')}/"

    def PassManRedirect(self):
        if Store.DIR_MAIN != "":
            self.win = Ui_PassManager()
            self.win.show()

        else:
            ShowDialog.ShwError(self, "Please Choose a Directory")

    def backend(self):
        if Store.DIR_MAIN != "":
            if os.path.exists(f"{Store.DIR_MAIN}Locker"):
                SecFile = open(f"{Store.DIR_MAIN}SecOps.json", "r")
                Data = json.load(SecFile)
                SecFile.close()
                
                Store.key = base64.b64decode(Data['SEC_KEY'].encode())
                Store.iv = base64.b64decode(Data['SEC_IV'].encode())
                State = Data['STATE']
                Store.PasswordHash = Data['PasswordHash']

                if State == "UNSAFE":
                    self.win = Ui_EncryptLocker()
                    self.win.show()

                elif State == "SAFE":
                    self.win = Ui_DecryptLocker()
                    self.win.show()

            else:
                self.win = Ui_MakeLocker()
                self.win.show()
        
        else:
            ShowDialog.ShwError(self, "Please Choose a Directory")

class Ui_MakeLocker(QMainWindow):
    def __init__(self):
        super(Ui_MakeLocker, self).__init__()

        self.setObjectName("CreateLocker")
        self.setFixedSize(792, 250)
        self.mainLabel = QtWidgets.QLabel(self)
        self.mainLabel.setGeometry(QtCore.QRect(295, 20, 221, 41))
        self.mainLabel.setObjectName("mainLabel")
        self.pasLabel = QtWidgets.QLabel(self)
        self.pasLabel.setGeometry(QtCore.QRect(180, 90, 141, 31))
        self.pasLabel.setObjectName("pasLabel")
        self.crtBtn = QtWidgets.QPushButton(self)
        self.crtBtn.setGeometry(QtCore.QRect(330, 160, 141, 51))
        self.crtBtn.setStyleSheet("color: rgb(255, 255, 255);\n"
"background-color: rgb(0, 170, 0);\n"
"border-radius: 15px;")
        self.crtBtn.setObjectName("crtBtn")
        self.crtBtn.clicked.connect(self.backend)
        self.passEdit = QtWidgets.QLineEdit(self)
        self.passEdit.setGeometry(QtCore.QRect(330, 90, 291, 31))
        self.passEdit.setStyleSheet("background-color: rgb(62, 62, 62);\n"
"color: rgb(255, 255, 255);\n"
"font: 12pt \"Cantarell\";\n"
"border-radius: 10px;")
        self.passEdit.setObjectName("passEdit")

        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("CreateLocker", "Create Locker"))
        self.mainLabel.setText(_translate("CreateLocker", "<html><head/><body><p align=\"center\"><span style=\" font-size:22pt; text-decoration: underline;\">Create Locker</span></p></body></html>"))
        self.pasLabel.setText(_translate("CreateLocker", "<html><head/><body><p align=\"center\"><span style=\" font-size:14pt;\">Give Password</span></p></body></html>"))
        self.crtBtn.setText(_translate("CreateLocker", "Create"))
        self.passEdit.setPlaceholderText(_translate("CreateLocker", "Password"))

        self.show()

    def backend(self):
        pas = self.passEdit.text()
        KEY = base64.b64encode(os.urandom(32)).decode()
        IV = base64.b64encode(os.urandom(16)).decode()
        hashed = hashlib.sha256(pas.encode()).hexdigest()

        SecFile = open(f"{Store.DIR_MAIN}SecOps.json", "w")

        dic = {
                "PasswordHash":hashed, 
                "SEC_KEY":KEY, 
                "SEC_IV":IV,
                "STATE":"UNSAFE"
                }
        json.dump(dic, SecFile)
        SecFile.close()

        os.mkdir("Locker")
        ShowDialog.ShwSuc(self, "Locker Created Sucessfully")


class Ui_EncryptLocker(QMainWindow):
    def __init__(self):
        super(Ui_EncryptLocker, self).__init__()
        self.setObjectName("EncryptLocker")
        self.setFixedSize(792, 250)
        self.mainLabel = QtWidgets.QLabel(self)
        self.mainLabel.setGeometry(QtCore.QRect(310, 20, 221, 41))
        self.mainLabel.setObjectName("mainLabel")
        self.pasLabel = QtWidgets.QLabel(self)
        self.pasLabel.setGeometry(QtCore.QRect(190, 90, 111, 19))
        self.pasLabel.setObjectName("pasLabel")

        self.encBtn = QtWidgets.QPushButton(self)
        self.encBtn.setGeometry(QtCore.QRect(340, 160, 141, 51))
        self.encBtn.setStyleSheet("color: rgb(255, 255, 255);\n"
"background-color: rgb(0, 170, 0);\n"
"border-radius: 15px;")
        self.encBtn.setObjectName("encBtn")
        self.encBtn.clicked.connect(self.backend)
        self.passEdit = QtWidgets.QLineEdit(self)
        self.passEdit.setGeometry(QtCore.QRect(300, 90, 291, 27))
        self.passEdit.setStyleSheet("background-color: rgb(62, 62, 62);\n"
"color: rgb(255, 255, 255);\n"
"font: 12pt \"Cantarell\";\n"
"border-radius: 10px;")
        self.passEdit.setObjectName("passEdit")
        self.passEdit.setEchoMode(QLineEdit.Password)

        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("EncryptLocker", "Encrypt Locker"))
        self.mainLabel.setText(_translate("EncryptLocker", "<html><head/><body><p align=\"center\"><span style=\" font-size:22pt; text-decoration: underline;\">Encrypt Locker</span></p></body></html>"))
        self.pasLabel.setText(_translate("EncryptLocker", "<html><head/><body><p align=\"center\"><span style=\" font-size:14pt;\">Password</span></p></body></html>"))
        self.encBtn.setText(_translate("EncryptLocker", "Encrypt"))
        self.passEdit.setPlaceholderText(_translate("EncryptLocker", "Password"))

        self.show()

    def backend(self):
        backend = default_backend()
        SecFile = open(f"{Store.DIR_MAIN}SecOps.json", "r")
        Data = json.load(SecFile)
        SecFile.close()

        def padding(data):
            while len(data) % 16 != 0:
                data = data + " "
            return data
        
        def encrypt(inp):
            padded_msg = padding(inp).encode()
            cipher = Cipher(algorithms.AES(Store.key), modes.CBC(Store.iv), backend=backend)
            encryptor = cipher.encryptor()
            ct = encryptor.update(padded_msg) + encryptor.finalize()
            b64 = base64.b64encode(ct).decode()
            return b64
        
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
        
        hashed = hashlib.sha256(self.passEdit.text().encode()).hexdigest()
        if Data['PasswordHash'] == hashed:
            dir_enc(f"{Store.DIR_MAIN}Locker/")

            SecFile = open(f"{Store.DIR_MAIN}SecOps.json", "w")
            Data['STATE'] = "SAFE"
            json.dump(Data, SecFile)
            SecFile.close()
            ShowDialog.ShwSuc(self, "Data Encrypted successfully")
        
        else:
            ShowDialog.ShwError(self, "Wrong Password!")

class Ui_DecryptLocker(QMainWindow):
    def __init__(self):
        super(Ui_DecryptLocker, self).__init__()
        self.setObjectName("DecryptLocker")
        self.setFixedSize(792, 250)
        self.mainLabel = QtWidgets.QLabel(self)
        self.mainLabel.setGeometry(QtCore.QRect(310, 20, 221, 41))
        self.mainLabel.setObjectName("mainLabel")
        self.pasLabel = QtWidgets.QLabel(self)
        self.pasLabel.setGeometry(QtCore.QRect(190, 90, 111, 19))
        self.pasLabel.setObjectName("pasLabel")
        
        self.decBtn = QtWidgets.QPushButton(self)
        self.decBtn.setGeometry(QtCore.QRect(340, 150, 141, 51))
        self.decBtn.setStyleSheet("color: rgb(255, 255, 255);\n"
"background-color: rgb(0, 170, 0);\n"
"border-radius: 15px;")
        self.decBtn.setObjectName("decBtn")
        self.decBtn.clicked.connect(self.backend)
        self.passEdit = QtWidgets.QLineEdit(self)
        self.passEdit.setGeometry(QtCore.QRect(300, 90, 291, 27))
        self.passEdit.setStyleSheet("background-color: rgb(62, 62, 62);\n"
"color: rgb(255, 255, 255);\n"
"font: 12pt \"Cantarell\";\n"
"border-radius: 10px;")
        self.passEdit.setObjectName("passEdit")
        self.passEdit.setEchoMode(QLineEdit.Password)

        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("DecryptLocker", "Decrypt Locker"))
        self.mainLabel.setText(_translate("DecryptLocker", "<html><head/><body><p align=\"center\"><span style=\" font-size:22pt; text-decoration: underline;\">Decrypt Locker</span></p></body></html>"))
        self.pasLabel.setText(_translate("DecryptLocker", "<html><head/><body><p align=\"center\"><span style=\" font-size:14pt;\">Password</span></p></body></html>"))
        self.decBtn.setText(_translate("DecryptLocker", "Decrypt"))
        self.passEdit.setPlaceholderText(_translate("DecryptLocker", "Password"))

        self.show()

    def backend(self):
        backend = default_backend()
        SecFile = open(f"{Store.DIR_MAIN}SecOps.json", "r")
        Data = json.load(SecFile)
        SecFile.close()

        def decrypt(inp):
            paa = inp.encode()
            b64 = base64.b64decode(paa)
            cipher = Cipher(algorithms.AES(Store.key), modes.CBC(Store.iv), backend=backend)
            decryptor = cipher.decryptor()
            dec = decryptor.update(b64) + decryptor.finalize()
            return dec.rstrip().decode()

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
                        
                        else:
                            ShowDialog.ShwError(self, "Unknown Extension Detected")
                
                    elif os.path.isdir(f"{DIR}{file}"):
                        dir_dec(f"{DIR}{file}/")
                
                except Exception:
                    continue
        
        hashed = hashlib.sha256(self.passEdit.text().encode()).hexdigest()
        if Data['PasswordHash'] == hashed:
            dir_dec(f"{Store.DIR_MAIN}Locker/")

            SecFile = open(f"{Store.DIR_MAIN}SecOps.json", "w")
            Data['STATE'] = "UNSAFE"
            json.dump(Data, SecFile)
            SecFile.close()
            ShowDialog.ShwSuc(self, "Data Decrypted successfully")

        else:
            ShowDialog.ShwError(self, "Wrong Password!")

class Ui_PassManager(QMainWindow):
    def __init__(self):
        super(Ui_PassManager, self).__init__()
        self.setObjectName("EncryptLocker")
        self.setFixedSize(792, 306)
        self.mainLabel = QtWidgets.QLabel(self)
        self.mainLabel.setGeometry(QtCore.QRect(280, 20, 271, 41))
        self.mainLabel.setObjectName("mainLabel")
        self.pasLabel = QtWidgets.QLabel(self)
        self.pasLabel.setGeometry(QtCore.QRect(150, 90, 141, 19))
        self.pasLabel.setObjectName("pasLabel")
        self.dirLabel = QtWidgets.QLabel(self)
        self.dirLabel.setGeometry(QtCore.QRect(150, 150, 151, 31))
        self.dirLabel.setObjectName("dirLabel")
        self.manBtn = QtWidgets.QPushButton(self)
        self.manBtn.setGeometry(QtCore.QRect(340, 220, 141, 51))
        self.manBtn.setStyleSheet("color: rgb(255, 255, 255);\n"
"background-color: rgb(0, 170, 0);\n"
"border-radius: 15px;")
        self.manBtn.setObjectName("manBtn")
        self.manBtn.clicked.connect(self.backend)
        self.passEdit = QtWidgets.QLineEdit(self)
        self.passEdit.setGeometry(QtCore.QRect(300, 90, 311, 27))
        self.passEdit.setStyleSheet("background-color: rgb(62, 62, 62);\n"
"color: rgb(255, 255, 255);\n"
"font: 12pt \"Cantarell\";\n"
"border-radius: 10px;")
        self.passEdit.setObjectName("passEdit")
        self.passEdit.setEchoMode(QLineEdit.Password)
        self.dirEdit = QtWidgets.QLineEdit(self)
        self.dirEdit.setGeometry(QtCore.QRect(300, 150, 311, 27))
        self.dirEdit.setStyleSheet("background-color: rgb(62, 62, 62);\n"
"color: rgb(255, 255, 255);\n"
"font: 12pt \"Cantarell\";\n"
"border-radius: 10px;")
        self.dirEdit.setObjectName("dirEdit")

        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("EncryptLocker", "Encrypt Locker"))
        self.mainLabel.setText(_translate("EncryptLocker", "<html><head/><body><p align=\"center\"><span style=\" font-size:22pt; text-decoration: underline;\">Password Manager</span></p></body></html>"))
        self.pasLabel.setText(_translate("EncryptLocker", "<html><head/><body><p align=\"center\"><span style=\" font-size:14pt;\">Old Password</span></p><p align=\"center\"><br/></p></body></html>"))
        self.dirLabel.setText(_translate("EncryptLocker", "<html><head/><body><p align=\"center\"><span style=\" font-size:14pt;\">New Password</span></p></body></html>"))
        self.manBtn.setText(_translate("EncryptLocker", "Change"))
        self.passEdit.setPlaceholderText(_translate("EncryptLocker", "Old Password"))
        self.dirEdit.setPlaceholderText(_translate("EncryptLocker", "New Password"))

        self.show()

    def backend(self):
        fl = open(f"{Store.DIR_MAIN}SecOps.json", "r")
        Data = json.load(fl)
        fl.close()

        hashed = hashlib.sha256((self.passEdit.text()).encode()).hexdigest()

        if Data['PasswordHash'] == hashed:
            if len(self.dirEdit.text()) != 0:
                newHash = hashlib.sha256((self.dirEdit.text()).encode()).hexdigest()
                SecFile = open(f"{Store.DIR_MAIN}SecOps.json", "w")
                Data['PasswordHash'] = newHash
                json.dump(Data, SecFile)
                SecFile.close()
                ShowDialog.ShwSuc(self, "Password Updated Sucessfully")
            
            else:
                ShowDialog.ShwError(self, "Don't give a blank Password!")
        
        else:
            ShowDialog.ShwError(self, "Wrong Password!")

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    ui = Ui_main()
    sys.exit(app.exec_())
