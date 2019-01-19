# -*- coding: utf-8 -*-
# Copyright (c) 2016
#
# Comaptible with Python 2.7 + and Python 3.x
#
# With this script you can encrypt and decrypt a given file with AES_OFB (Output Feedback).
#
# The script will guide you through the process:-)
#
# Author:
#   Xenia Bogomolec, indigomind@gmx.de, xenia.bogomolec@extern.polizei.niedersachsen.de
#
################################################################################################
########################################### FUNCTIONS ##########################################
################################################################################################

import binascii, hashlib, io, os, platform, subprocess, sys
from base64 import *
from datetime import datetime
from Crypto.Cipher import AES


# global variables
osPlatform = platform.system().lower()
AES_args = {}
pic_formats = ["jpg", "png", "tif"]
actions = {
    'e': 'Encrypting',
    'd': 'Decrypting',
    't': 'Testing'
}


#################################### PYTHON VERSION VARIANTS ##################################

def v_bytes(string):
    return bytes(string, "utf-8") if sys.version_info[0] == 3 else string

def v_input(string):
    return input(string) if sys.version_info[0] == 3 else raw_input(string)



################################## OS RELATED TERMINAL VARIANTS ###############################    

def clearConsole():
    if osPlatform.startswith("win"):
        os.system("cls")
    elif osPlatform.startswith("linux"):
        # does not work on my new machine with Ubuntu 18.04
        os.system("history -c")
    else:
        print("Make sure to clear your command line history after running the script!!!")

def terminalSize():
    if osPlatform.startswith("linux"):
        os.system("resize -s 40 120")
        return 120
    elif osPlatform.startswith("win"):
        os.system("mode con: cols=120 lines=40")
        return 120
    else: 
        return 80


######################################### CIPHER CLASS ########################################

class Cipher(object):

    start_crypto = 0
    end_crypto = 0
    AES_modes = {"OFB": AES.MODE_OFB}
    required_args = ["-a", "-f", "-u", "-k"]
    usage = """

This is the file encrypter! Run it like this: 

  python cryptFile.py -a action -f file -u user -k key

  1. where action is e for encrypt, d for decrypt or t for testing
  2. file is the path to the file
  3. user is a username (min length = 6 characters) 
  4. key is the key (min length = 8 characters) 

Keep user and key in your own mind! 
They will not be stored or hidden by the script.
If you forget them, encrypted files cannot not be decrypted anymore in reasonable time.

        """

    def start(self, argv):

        if len(argv) == 1:
            print(self.usage)
            sys.exit()

        self.parse_args(argv)
        self.prepareArgs()

        if AES_args["-a"] == "e":
            self.encryptFile()
        if AES_args["-a"] == "d":
            self.decryptFile()
        if AES_args["-a"] == "t":
            self.testDecryption()

    ### build a dictionary of valid arguments 
    def parse_args(self, strings):
        missing_args = set(self.required_args) - set(strings)
        if len(strings) < 9:
            print("\nMissing arguments!")
        if len(missing_args) > 0:
            for arg in missing_args:
                print("   You forgot to define %s" % (arg))
            sys.exit()
        for arg in self.required_args:
            try:
                AES_args[arg] = strings[strings.index(arg) + 1]
            except:
                print("   You have to define the value of %s" % (arg))
    
        # lower bound for security param 
        if AES_args["-a"] == "e" and (len(AES_args["-u"]) < 12 or len(AES_args["-k"]) < 6):
            print("\n   The key and user must consist of 12 characters at least")
            sys.exit()
        # security param check
        if AES_args["-a"] == "e" and (len(AES_args["-k"]) < 12):
            print("\n   It is recommended to use a key and user name with 24 characters in total at least") 
            go_on = v_input("\n   Are you sure that you want to continue? Type y/n for yes/no: ")
            if go_on == "n":
                sys.exit()
        clearConsole()
        print("\n%s %s ..." % (actions[AES_args["-a"]], AES_args["-f"]))
        return AES_args

    ### prepare arguments for encryption
    def prepareArgs(self):
        if AES_args["-a"] not in ["e", "d", "t"]:
            print("\n-a must be e for encryption or d for decryption")
            sys.exit()
        self.start_crypto = datetime.now()
        AES_args["-f"] = AES_args["-f"].replace("\\", "/")
        AES_args["-k"] = self.buildKey(AES_args["-k"], 251)
        # create an initialization vector from the user name
        AES_args["-u"] = self.buildKey(AES_args["-u"], 239)[11:27]

    ### create a HMAC of key and user name
    def buildKey(self, key, modulus):
        salt, index = v_bytes(""), 0
        # build own salt on the basis of given key
        for i in 4*key:
            index += 1
            hexPosition = hex(int(binascii.hexlify(v_bytes(i)), 16)**index % modulus)[2:4].replace("L", "")
            hexPosition = "0" + hexPosition if len(hexPosition) == 1 else hexPosition
            salt += binascii.unhexlify(hexPosition) 
        # create a HMAC of the given key with the created salt
        newKey = hashlib.pbkdf2_hmac("sha512", v_bytes(key), salt, 2746398)
        return newKey[17:49]

    ### block cipher encryption 
    def encryptFile(self):
        with open(AES_args["-f"], "rb") as readFile:
            plaintext = b64encode(readFile.read())
            plaintext += (16-len(plaintext)%16)*b'\x00' # padding
        obj = AES.new(AES_args["-k"], self.AES_modes["OFB"], AES_args["-u"])
        ciphertext = obj.encrypt(plaintext)
        self.writeFile(ciphertext, "_encrypted.")

    ### block cipher decryption 
    def decryptFile(self):
        with open(AES_args["-f"], "rb") as readFile:
            ciphertext = readFile.read()
            # for text files written on windows systems
            if AES_args["-f"].split(".").pop() not in pic_formats:
                hextext = binascii.hexlify(ciphertext).replace(b"0d0a", b"0a")
                ciphertext = binascii.unhexlify(hextext)
        obj = AES.new(AES_args["-k"], self.AES_modes["OFB"], AES_args["-u"])
        try:
            decryptedtext = obj.decrypt(ciphertext)
            decryptedtext = b64decode(decryptedtext)
            self.writeFile(decryptedtext, "_decrypted.")
        except:
            print("\n   Are you sure you chose the right action for the file? \n   %s seems not to be encrypted with this script.\n" % (AES_args["-f"]))

    ### testing encryption and decryption without saving encrypted version
    def testDecryption(self):
        print("\ntesting the encryption-decryption-process without saving encryption to a file")
        #encryption
        with open(AES_args["-f"], "rb") as readFile:
            plaintext = b64encode(readFile.read())
            plaintext += (16-len(plaintext)%16)*b'\x00' # padding
        obj = AES.new(AES_args["-k"], self.AES_modes["OFB"], AES_args["-u"])
        ciphertext = obj.encrypt(plaintext)
        # decryption
        obj2 = AES.new(AES_args["-k"], self.AES_modes["OFB"], AES_args["-u"])
        decryptedtext = obj2.decrypt(ciphertext)
        decodedtext = b64decode(decryptedtext)
        self.writeFile(decodedtext, "_tested.")

    ### writing file
    def writeFile(self, text, direction):
        self.end_crypto = datetime.now()
        pathParts = AES_args["-f"].split(".")
        filePath = pathParts[0] + direction + pathParts[1]       
        fileName = filePath.split("/").pop()
        changedName = v_input("\nThe new file name will be %s. If you want another name, type it, else just press enter: " % (fileName))
        print(changedName)
        newFileName = fileName if changedName == "" else changedName.split(".")[0] + "." + fileName.split(".").pop() # make sure to get right file format
        newFilePath = filePath.replace(fileName, newFileName)
        with open(newFilePath, "wb") as newFile:
            newFile.write(text)
        self.cleanUp(newFileName, newFilePath)

    ### cleaning up
    def cleanUp(self, newFileName, newFilePath):
        width = terminalSize()
        print("\n%s" % (width * "-"))
        print("%s saved in %s" % (newFileName, newFilePath.replace(newFileName, "")))
        print("\nComputation time: %s" % (str(self.end_crypto - self.start_crypto)[2:]))
        print("%s" % (width * "-"))
        delete = v_input("\nDo you want to delete the original file? Type y/n for yes/no: ")
        if delete == "y":
            os.remove(AES_args["-f"])
            print("Deleted %s\n" % (AES_args["-f"]))
        if osPlatform.startswith("linux"):
            print("type 'history -c' to clear the current command line history")


if __name__ == '__main__':

    Cipher().start(sys.argv)



#
#
#                          m    m      \           /      m    m   
#                      m            m   \    n    /   m            m
#                       m              m \  OOO  / m              m
#                         m              m\/ Ö \/m              m
#                            m             mÖÖÖm            m
#                                 m    m    ÖÖÖ    m    m
#                                    m   m   Ö   m   m
#                           m               /Ö\              m
#                       m              |   / Ö \   |             m
#                     m               m   !  Ö  !   m              m
#                      m          m   /   !  Ö  !   \   m          m
#                         m  m            !  Ö  !           m  m
#                                        /   Ö   \
#                                            Ö
#                                            Ö
#                                            Ö
#                                            Ö
#                                            Ö
#
#