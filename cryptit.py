#!/usr/bin/python3

import argparse
from functools import partial
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Hash import *
from Crypto.Hash import SHAKE128
from Crypto.Hash import SHAKE256
from Crypto.Hash import MD4
from Crypto.Hash import SHA3_224
from Crypto.Hash import SHA3_256
from Crypto.Hash import SHA3_384
from Crypto.Hash import SHA3_512
from Crypto.Cipher import *
from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from Crypto.Cipher import DES3

BUF_SIZE    = 65536
SALT = b"\xdf\x1f\x2d\x3f\x4d\x77\xac\x66\xe9\xc5\xa6\xc3\xd8\xf9\x21\xb6"
hash_funcs  = {
    "SHA-1"      : SHA1, 
    "MD2"        : MD2, 
    "MD4"        : MD4, 
    "MD5"        : MD5, 
    "RIPEMD-160" : RIPEMD160, 
    "SHA-224"    : SHA224, 
    "SHA-256"    : SHA256, 
    "SHA-384"    : SHA384, 
    "SHA-512"    : SHA512,
    "SHA3-224"   : SHA3_224,
    "SHA3-256"   : SHA3_256,
    "SHA3-384"   : SHA3_384,
    "SHA3-512"   : SHA3_512,
    "SHAKE-128"  : SHAKE128,
    "SHAKE-256"  : SHAKE256
}
crypt_funcs = [
    "AES-128",
    "AES-192",
    "AES-256",
    "DES3",
    "BLOWFISH"
]
modes = ["CBC", "ECB", "CFB", "OFB", "CTR", "EAX"]

def main():
    args = parse()
    if (args.encrypt):
        encrypt(args)
    elif (args.decrypt):
        decrypt(args)
    elif (args.hash):
        hash(args)

def encrypt(args):
    if (args.file):
        with open(args.file.name + ".enc", "wb") as f:
            if (args.cipher == "DES3"):
                key = PBKDF2(args.password, count=1000000, salt=SALT, dkLen=24)
            elif ("AES" in args.cipher):
                keylen = 0
                if (args.cipher == "AES-128"): 
                    keylen = 16
                elif (args.cipher == "AES-192"): 
                    keylen = 24
                elif (args.cipher == "AES-256"): 
                    keylen = 32
                key = PBKDF2(args.password, count=100, salt=SALT, dkLen=keylen)
                cipher = AES.new(key, AES.MODE_ECB)
                for plaintext in iter(partial(args.file.read, BUF_SIZE), b''):
                    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
                    f.write(ciphertext) 
            elif (args.cipher == "BLOWFISH"):
                key = args.password
            print("Encrypted content saved to " + f.name)

def decrypt(args):
    if (args.file):
        with open(args.file.name[:-4], "wb") as f:
            if (args.cipher == "DES3"):
                key = PBKDF2(args.password, count=1000000, salt=SALT, dkLen=24)
            elif ("AES" in args.cipher):
                keylen = 0
                if (args.cipher == "AES-128"): 
                    keylen = 16
                elif (args.cipher == "AES-192"): 
                    keylen = 24
                elif (args.cipher == "AES-256"): 
                    keylen = 32
                key = PBKDF2(args.password, count=100, salt=SALT, dkLen=keylen)
                cipher = AES.new(key, AES.MODE_ECB)
                for ciphertext in iter(partial(args.file.read, BUF_SIZE), b''):
                    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
                    f.write(plaintext) 
            elif (args.cipher == "BLOWFISH"):
                key = args.password
            print("Decrypted content saved to " + f.name)

def hash(args):
    hashObj = hash_funcs[args.cipher.toUpper()].new()
    if (args.string):
        hashObj.update(args.string.encode())
    elif (args.file):
        buf = args.file.read(BUF_SIZE)
        while (buf != ""):
            hashObj.update(buf.encode())
            buf = args.file.read(BUF_SIZE)
    print(hashObj.hexdigest())

def parse():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files and strings of text using symmetric or asymmetric cryptography.")

    actionGroup = parser.add_mutually_exclusive_group(required=True)
    actionGroup.add_argument("-e", "--encrypt", action="store_true", help="Flag the payload for encryption.")
    actionGroup.add_argument("-d", "--decrypt", action="store_true", help="Flag the payload for decryption.")
    actionGroup.add_argument("-H", "--hash", action="store_true", help="Flag the payload for hashing.")

    payloadGroup = parser.add_mutually_exclusive_group(required=True)
    payloadGroup.add_argument("-f", "--file", type=argparse.FileType('rb'), help="Pass a file for processing.")
    payloadGroup.add_argument("-s", "--string", type=str, help="Enter a string for processing (please use quotes around your text \"\")")

    parser.add_argument("-c", "--cipher", type=str, required=True, help="Declare the cryptographic algorithm to use.")
    parser.add_argument("-p", "--password", type=str, help="Password used for encryption.")
    parser.add_argument("-m", "--mode", type=str, help="Declare the encryption mode (only works on some ciphers).")

    args = parser.parse_args()
    if ((args.encrypt or args.decrypt) and not args.password):
        print("Encrytion and decryption require a password")
        exit(0)
    elif (args.mode not in modes):
        print("Invalid encryption mode.")
        exit(0)
    elif (args.hash and (args.password or args.mode)):
        print("Hashing does not take a password parameter nor a mode parameter.")
        exit(0)
    elif (args.decrypt and ".enc" != args.file.name[-4:]):
        print("Files to decrypt must end in the .enc extension.")
        exit(0)
    if (args.hash and args.cipher in hash_funcs
        or (args.encrypt or args.decrypt) 
        and (args.cipher in crypt_funcs)):
        return args
    else:
        print("Hashing calls must be paired with valid hash functions and encryption/decryption with valid encryption algorithms.")
        exit(0)

if __name__ == "__main__":
    main()