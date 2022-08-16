import hashlib
from hashlib import *
import os
import marshal
os.system("clear")
st = """\033[31m
 _   _ BASSAM v2 _   _____           _ 
| | | | __ _ ___| |_|_   _|__   ___ | |
| |_| |/ _` / __| '_ \| |/ _ \ / _ \| |
|  _  | (_| \__ \ | | | | (_) | (_) | |
|_| |_|\__,_|___/_| |_|_|\___/ \___/|_|
"""
print(st)

print("\033[33m======================================")
print("Hash Chacker[1]\nHash Length[2]\nHash Type[3]\nMD5 Encrypt[4]\nMD5 Decrypt[5]\nEncrypt File[6]")
print("======================================")
try:

    choose = input("\033[36mChoose Option : ")
    if choose == "1":
        print("\033[39mThis Option For Hash Checker ")
        hash1 = input("Enter Hash 1 : ")
        hash2 = input("Enter Hash 2 : ")
        if hash1 == hash2 :
            print("It's Cool..!")
        else:
            print("It's edit [HACKED]")
    elif choose == "2":
        print("\033[39mThis Option For Hash Length ")
        lnhash = input("Type Your Hash : ")
        print ("Your Length Hash is > " , len(lnhash))
    elif choose == "3":
        print("\033[39mThis Option For Hash Type")
        hash = input("Enter Your Hash : ")
        len = len(hash)
        if len == 32 :
            print("Your Hash Is [MD5]")
        elif len == 40 :
            print("Your Hash Is [sha1]")
        elif len == 64 :
            print("Your Hash Is [sha256]")
    elif choose == "4":
        print("\033[39mThis Option For MD5 Encypt ")
        word = input("Enter Your Text : ")
        md5 = hashlib.md5(word.encode())
        print(md5.hexdigest())
    elif choose == "5":
        print("\033[39mThis Option For MD5 Decrypt ")
        hash = input("Enter Your Hash : ")
        file = input("Write The File Name : ")
        with open(file, mode="r") as f :
            for li in f :
                li =li.strip()
                if md5(li.encode()).hexdigest() == hash :
                    print("[+] Password Found : "+li)
    elif choose == "6":
        print("[-] the file should be in path file here you are ")
        file_org = input("Enter the path file : ")
        open_read = open(file_org).read()
        compi = compile(open_read, "","exec")
        dumps_march = marshal.dumps(compi)
        end_fi = open("encrypt-" + file_org,"w")
        end_fi.write("import marshal\n")
        end_fi.write("exec(marshal.loads("+repr(dumps_march)+"))")
        end_fi.close()
        print("[+] Done ...")


    else:
        print("\033[39m********************")
        print("\033[39mOption Not Found X_x")
        print("********************")
except:
    print("ERROR 404")


