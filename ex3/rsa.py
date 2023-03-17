import random
import math

from Crypto.Cipher import AES
from Crypto.Hash import SHA1
from Crypto.Util import Padding

k0 = 8
k1 = 8
m = 16


def bitstring_xor(a, b):
    ans = ""
    for i in range(len(a)):
        if a[i] != b[i]:
            ans += "1"
        else:
            ans += "0"
    return ans

def bin_to_byte(binary):
    bin_list = [binary[i:i + 8] for i in range(0, len(binary), 8)]
    bin_int = [int(x, 2) for x in bin_list]
    return bytes(bin_int)

def xgcd(a, b):  # from https://anh.cs.luc.edu/331/code/xgcd.py
    prevx, x = 1, 0;
    prevy, y = 0, 1
    while b:
        q, r = divmod(a, b)
        x, prevx = prevx - q * x, x
        y, prevy = prevy - q * y, y
        a, b = b, r
    return a, prevx, prevy


def get_primes(lim, double=False):
    sieve = [True] * lim
    sieve[0] = sieve[1] = False
    primes = []
    for i in range(2, lim):
        if sieve[i]:
            primes.append(i)
            w = 2 * i
            while w < lim:
                sieve[w] = False
                w += i
    if double:
        p, q = random.choices(primes, k=2)
        while p * q < 4_294_967_296 or p == q:
            p, q = random.choices(primes, k=2)
        return p, q
    else:
        return random.choice(primes)


def RSA_prepare(p, q):
    N = p * q
    fi = (p - 1) * (q - 1)
    e = fi
    while math.gcd(e, fi) != 1 or e % 2 != 1:
        e = random.randint(1, fi)
    tmp_d = xgcd(e, fi)[1]
    if tmp_d < 0:
        d = fi + tmp_d
    else:
        d = tmp_d
    return N, e, d


def vanilla_encrypt(message, N, e):
    # we need block of size 32b
    message = prepare_message(message, 4)
    ans = []
    for i in range(0, len(message), 4):
        bits = ""
        sub_mess = message[i:i+4]
        for letter in sub_mess:
            bits += bin(ord(letter))[2:].zfill(8)
        to_encrypt = int(bits, 2)
        ans.append(pow(to_encrypt, e, N))
    return ans


def vanilla_decrypt(cipher, N, d):
    ans = ""
    for num in cipher:
        decrypted = bin(pow(num, d, N))[2:].zfill(32)
        decrypted = [decrypted[i:i+8] for i in range(0, len(decrypted), 8)]
        for part in decrypted:
            ans += chr(int(part,2))
    return ans


def RSA_OAEP_encrypt(message, N, e):
    multi = 2
    # each block consist of 2 letters, 1 byte of 0s and 1 byte of
    ans = []
    for i in range(0, len(message), multi):
        num = ""
        for j in range(i, i + multi):
            num += bin(ord(message[j]))[2:].zfill(8)
        num += "0" * k1
        R = bin(random.randint(1, 2 ** k0))[2:].zfill(k0)
        G_box = SHA1.new(bin_to_byte(R))
        g = bin(int(G_box.hexdigest(), 16))[2:m + k1 + 2]
        mXg = bitstring_xor(num, g)
        mXg_list = [mXg[i:i + 8] for i in range(0, len(mXg), 8)]
        mXg_int = [int(x, 2) for x in mXg_list]
        H_box = SHA1.new(bytes(mXg_int))
        h = bin(int(H_box.hexdigest(), 16))[2:k0 + 2]
        Y = bitstring_xor(h, R)
        X = mXg
        input_bitstring = X + Y
        input_int = int(input_bitstring, 2)
        c = pow(input_int, e, N)
        ans.append(c)
    return ans


def RSA_OAEP_decrypt(ciphertext, N, d):
    ans = ""
    for el in ciphertext:
        m_el = pow(el, d, N)
        m_bit = bin(m_el)[2:]
        X = m_bit[:m + k1]
        Y = m_bit[m + k1:]
        H_box = SHA1.new(bin_to_byte(X))
        h = bin(int(H_box.hexdigest(), 16))[2:k0 + 2]
        R = bitstring_xor(Y, h)
        R_int = [int(R, 2)]
        G_box = SHA1.new(bytes(R_int))
        g = bin(int(G_box.hexdigest(), 16))[2:m + k1 + 2]
        Xxg = bitstring_xor(X, g)[:m]
        m_list = [Xxg[i:i + 8] for i in range(0, len(Xxg), 8)]
        m_char = [chr(int(letter, 2)) for letter in m_list]
        ans += m_char[0] + m_char[1]
    return ans


def hybrid_RSA_encrypt(message, N, e):
    # 32 bits for secret key
    key = []
    sk_list = []
    for _ in range(4):
        session_key = random.randint(2**24, 2 ** 32)
        c1 = pow(session_key, e, N)
        key.append(c1)
        sk_bin = bin(session_key)[2:]
        sk_list += ([int(sk_bin[i:i + 8], 2) for i in range(0, len(sk_bin), 8)])
    sk_bytesarray = bytearray(sk_list)
    box = AES.new(bytes(sk_bytesarray), mode=AES.MODE_ECB)
    message_bytes = bytes(message, "UTF-8")
    message_padded = Padding.pad(message_bytes, AES.block_size)
    cipher = box.encrypt(message_padded)
    return key, cipher


def hybrid_RSA_decrypt(cipher, key, N, d):
    sk_list = []
    for k in key:
        session_key = pow(k, d, N)
        sk_bin = bin(session_key)[2:]
        sk_list += ([int(sk_bin[i:i + 8], 2) for i in range(0, len(sk_bin), 8)])
    sk_bytesarray = bytearray(sk_list)
    box = AES.new(bytes(sk_bytesarray), mode=AES.MODE_ECB)
    message = Padding.unpad(box.decrypt(cipher), AES.block_size).decode("UTF-8")

    return message


def prepare_message(text, multiplicative_size):
    r = len(text) % multiplicative_size
    if r > 0:
        return text + "#" * (multiplicative_size - r)
    else:
        return text


if __name__ == "__main__":
    p, q = get_primes(100_000, True)
    N, e, d = RSA_prepare(p, q)

    message = prepare_message("HelloWorldYoursTrulySincerelyMe!", 2)

    ans = vanilla_encrypt(message, N, e)
    plain = vanilla_decrypt(ans, N, d)
    print(plain)


    ans = RSA_OAEP_encrypt(message, N, e)
    print(ans)
    new_message = RSA_OAEP_decrypt(ans, N, d)
    print(new_message)

    key, cipher = hybrid_RSA_encrypt(message, N, e)
    plain = hybrid_RSA_decrypt(cipher, key, N, d)
    print(plain)

    print("KW")
