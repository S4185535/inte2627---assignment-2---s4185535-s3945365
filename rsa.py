#rsa.py
#RSA digital signature: sign with private key d, verify with public key (e, n).
import hashlib

def hash_to_int(message):
    #Hash a string with SHA-256 and return it as an integer
    #ref: https://docs.python.org/3/library/hashlib.html
    digest = hashlib.sha256(message.encode()).hexdigest()
    return int(digest, 16)

def sign(hash_int, n, d):
    #s = m^d mod n
    return pow(hash_int, d, n)

def verify(hash_int, signature, n, e):
    #m = s^e mod n
    #Returns boolean
    return hash_int == pow(signature, e, n)