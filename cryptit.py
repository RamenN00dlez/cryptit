#!/usr/bin/python3

import argparse
from Crypto.Hash import *
from Crypto.Hash import SHAKE128
from Crypto.Hash import SHAKE256
from Crypto.Hash import MD4
from Crypto.Hash import SHA3_224
from Crypto.Hash import SHA3_256
from Crypto.Hash import SHA3_384
from Crypto.Hash import SHA3_512



BUF_SIZE    = 65536
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
crypt_funcs = []

def main():
    args = parse()
    '''
    if (args.encrypt):
        encrypt(args)
    elif (args.decrypt):
        decrypt(args)
    el'''
    if (args.hash):
        hash(args)
'''  
def encrypt(args):
    if (args.string):
    elif (args.file): 

def decrypt(args):
    if (args.string):
    elif (args.file):
'''
def hash(args):
    hashObj = hash_funcs[args.cipher].new()
    if (args.string):
        hashObj.update(args.string.encode())
        print(hashObj.hexdigest())
    elif (args.file):
        print(args.file.read())

def parse():
    parser = argparse.ArgumentParser(description="Encrypt or decrypt files and strings of text using symmetric or asymmetric cryptography.")

    actionGroup = parser.add_mutually_exclusive_group(required=True)
    actionGroup.add_argument("-e", "--encrypt", action="store_true", help="Flag the payload for encryption.")
    actionGroup.add_argument("-d", "--decrypt", action="store_true", help="Flag the payload for decryption.")
    actionGroup.add_argument("-H", "--hash", action="store_true", help="Flag the payload for hashing.")

    payloadGroup = parser.add_mutually_exclusive_group(required=True)
    payloadGroup.add_argument("-f", "--file", type=argparse.FileType('r'), help="Pass a file for processing.")
    payloadGroup.add_argument("-s", "--string", type=str, help="Enter a string for processing (please use quotes around your text \"\")")

    parser.add_argument("-c", "--cipher", type=str, required=True, help="Declare the cryptographic algorithm to use.")

    args = parser.parse_args()
    
    if (args.hash and args.cipher in hash_funcs
        or (args.encrypt or args.decrypt) and args.cipher in crypt_funcs):
        return args
    else:
        print("Hashing calls must be paired with valid hash functions and encryption/decryption with valid encryption algorithms.")

if __name__ == "__main__":
    main()