## Description

This is a command line utility program designed for quick and easy hashing of data files 
using as many hashing algorithms as we could find in the pycryptodome library.
encryption and decryption of data files using AES-128, AES-192, AES-128, and DES3 using the ECB, CBC, CFB, and OFB encryption modes.

## Usage

```bash
cryptit --hash --cipher SHA-256 --string "this is a string to hash"
fb921c43b622c389a08c232581bd334c36ede14c9f9b63b36381a48a78a04ea4
```
```bash
cryptit --encrypt --file file --cipher DES3 --password "SUPER-k00l_p4ssw0rd" --mode ECB
Encrypted content saved to file.enc
```
```bash
cryptit --decrypt --file file.enc --cipher DES3 --password "SUPER-k00l_p4ssw0rd" --mode ECB
Decrypted content saved to file
```