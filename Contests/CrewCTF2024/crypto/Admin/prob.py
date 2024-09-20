from os import urandom
from sys import exit
import string

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

blksize = AES.block_size


def getintinput(msg):
    opt = input(msg)
    try:
        opt = int(opt)
    except:
        return -1
    return opt


def gethexinput(msg):
    opt = input(msg)
    opt = opt.strip()
    if all([ele in string.hexdigits for ele in opt]):
        return opt.encode()
    else:
        return b""


def givetoken(key, i):
    iv = bytes.fromhex(gethexinput("iv(hex): ").decode())
    if len(iv) != blksize:
        print("iv is invalid.")
        return None
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    curusername = b'not_admin_username_' + str(i).encode()
    enc, tag = cipher.encrypt_and_digest(pad(curusername, blksize))
    return (curusername.decode(), iv.hex(), enc.hex(), tag.hex())


def checktoken(key):
    token = bytes.fromhex(gethexinput("token(hex): ").decode())
    if len(token) % blksize != 0 or len(token) <= 2*blksize:
        print("token is invalid.")
        return None
    iv = token[:blksize]
    tag = token[-blksize:]
    enc = token[blksize:-blksize]

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    try:
        dec = unpad(cipher.decrypt_and_verify(enc, tag), blksize)
    except ValueError:
        print("tag may be invalid.")
        return None
    if dec == b"admin":
        print("congrats, give you the flag.")
        flag = open('/flag.txt', 'rb').read().strip().decode()
        print(flag)
        return 1
    else:
        print("you are not admin user.")
        return 0


def banner():
    banner = [
        "#"*80,
        "AES challenge",
        "#"*80,
    ]
    print('\n'.join(banner))


def menu():
    menu = [
        "",
        "0: get token",
        "1: check admin token"
    ]
    print('\n'.join(menu))


def main():
    key = urandom(blksize)
    i = 0
    banner()
    try:
        while (True):
            menu()
            opt = getintinput("option(int): ")
            if opt == 0:
                result = givetoken(key, i)
                if result is None:
                    break
                curusername, iv, enc, tag = result
                print(f"token for {curusername} is: \n{iv + enc + tag}")
                i += 1
            elif opt == 1:
                result = checktoken(key)
                if result is None or result == 1:
                    break
            else:
                break
    except:
        print("error occured.")
        exit(1)

    print("bye")
    exit(0)


if __name__ == "__main__":
    main()
