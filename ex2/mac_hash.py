from base64 import b64encode
from binascii import hexlify

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor


def mac_hash(message: bytes, key:bytes):
    box = AES.new(sk, mode=AES.MODE_CBC)
    message = [message[i:i + AES.block_size] for i in range(0, len(message), AES.block_size)]
    Cm0 = box.encrypt(key)
    for m in message:
        Cm0 = box.encrypt(strxor(Cm0, m))
    tag = Cm0
    tag2 = box.encrypt(strxor(key, tag))

    print(hexlify(tag))
    print(hexlify(tag2))
    return tag2

if __name__ == "__main__":
    sk = bytes("\00"*16, "UTF-8")
    message = get_random_bytes(32)
    mac_hash(message, sk)

