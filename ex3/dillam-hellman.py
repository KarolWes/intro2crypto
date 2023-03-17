import random
from base64 import b64decode

from rsa import *

from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256


def prepare_key(key, size):
    bin_key = bin(key)[2:]
    bin_key += "0" * (size - len(bin_key))
    list_key = [int(bin_key[i:i + 8], 2) for i in range(0, size, 8)]
    byte_list = bytes(list_key)
    return byte_list

class Person:
    def __init__(self, name, private_key):
        self.name = name
        self.auth_key = RSA.generate(1024)
        self.password = str(random.randint(2**64, 2**80))
        f = open(self.name+".pem", "wb")
        f.write(self.auth_key.exportKey("PEM", self.password))
        f.close()
        self.full_key = None
        self.key = private_key
        self.partner_key = None
        self.partial_key = None

    def generate_partial_key(self, g, p):
        self.partial_key = pow(g, self.key, p)
        return self.partial_key

    def generate_full_key(self, partial_key):
        self.partner_key = partial_key
        self.full_key = pow(partial_key, self.key, p)

    def encrypt(self, message, b=False):
        box = AES.new(prepare_key(self.full_key,128), mode=AES.MODE_ECB)
        if b:
            return box.encrypt(Padding.pad(message, AES.block_size))
        else:
            return box.encrypt(Padding.pad(bytes(message, "UTF-8"), AES.block_size))

    def decrypt(self, message, b=False):
        box = AES.new(prepare_key(self.full_key, 128), mode=AES.MODE_ECB)
        if b:
            return box.decrypt(message)
        else:
            return Padding.unpad(box.decrypt(message), AES.block_size).decode("UTF-8")

    def get_public_key(self):
        return self.auth_key.public_key()

    def gen_auth(self):
        key_sum = bin(self.partial_key)[2:].zfill(32) + bin(self.partner_key)[2:].zfill(32)
        key_bytes = bin_to_byte(key_sum)
        signer = pkcs1_15.new(RSA.import_key(open(self.name+".pem").read(), self.password))
        h = SHA256.new(key_bytes)
        signature = signer.sign(h)
        enc_signature = self.encrypt(signature, b=True)
        return self.partial_key, enc_signature

    def verify_signature(self, enc_signature, partner_public):
        key_sum = bin(self.partner_key)[2:].zfill(32) + bin(self.partial_key)[2:].zfill(32)
        key_bytes = bin_to_byte(key_sum)
        signature = self.decrypt(enc_signature, b=True)
        h = SHA256.new(key_bytes)
        try:
            pkcs1_15.new(partner_public).verify(h, signature)
            return True
        except(ValueError, TypeError):
            return False


class Adversary(Person):
    def __init__(self, name, private_key):
        self.keys = {}
        self.counterpart = {"Alice": "Bob", "Bob": "Alice"}
        super().__init__(name, private_key)

    def intercept(self, payload, type, messenger):
        if type == "partial":
            self.keys[messenger] = payload
            return self.generate_partial_key(g, p)
        elif type == "message":
            self.generate_full_key(self.keys[messenger])
            plain = self.decrypt(payload)
            print(f"Intercepted message: {plain}")
            plain = "Hello you owe me 350"
            self.generate_full_key(self.keys[self.counterpart[messenger]])
            new_cipher = self.encrypt(plain)
            return new_cipher
        else:
            return payload

    def print_keys(self):
        print(self.keys)

    def clear(self):
        self.keys = {}


def channel(payload, type, messenger, attack=False):
    if not attack:
        output = payload
    else:
        output = Mallory.intercept(payload, type, messenger)
    return output





if __name__ == "__main__":
    Alice = Person("Alice", random.randint(2 ** 16, 2 ** 24))
    Bob = Person("Bob", random.randint(2 ** 16, 2 ** 24))
    Mallory = Adversary("Mallory", random.randint(2 ** 16, 2 ** 24))
    p = get_primes(10_000_000)
    g = 3
    alice_partial = Alice.generate_partial_key(g, p)
    bob_partial = Bob.generate_partial_key(g, p)
    Alice.generate_full_key(channel(bob_partial, "partial", "Bob", True))
    Bob.generate_full_key(channel(alice_partial, "partial", "Alice", True))
    Mallory.print_keys()
    print(f"Alice key: {Alice.full_key}, Bob key: {Bob.full_key}")

    m = Alice.encrypt("Hello you owe me 200")
    m = Bob.decrypt(channel(m, "message", "Alice", True))
    print(f"Bob's message: {m}")

    Mallory.clear()
    del Alice
    del Bob

    Alice = Person("Alice", random.randint(2 ** 16, 2 ** 24))
    Bob = Person("Bob", random.randint(2 ** 16, 2 ** 24))
    alice_partial = Alice.generate_partial_key(g, p)
    bob_partial = Bob.generate_partial_key(g, p)
    Bob.generate_full_key(channel(alice_partial, "partial", "Alice", True))
    Mallory.print_keys()
    payload = Bob.gen_auth()
    Alice.generate_full_key(channel(payload[0], "partial", "Bob", True))
    print(f"Alice key: {Alice.full_key}, Bob key: {Bob.full_key}")
    print(f"Verification: {Alice.verify_signature(payload[1], Bob.get_public_key())}")



    print("KW")
