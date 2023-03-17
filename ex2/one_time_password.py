import random
from Crypto.Hash import SHA1

ALPHABET="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,"


def initialize():
    sample = random.sample(range(64), 6)
    ot0 = ""
    for x in sample:
        ot0 += ALPHABET[x]
    return ot0

def generate_password(base:str):
    box = SHA1.new(bytes(base, "UTF-8"))
    h = bin(int(box.hexdigest(), 16))[2:].zfill(128)[:36]
    ot1 = ""
    for i in range(6):
        letter_bit = h[6*i:6*(i+1)]
        ot1 += ALPHABET[int(letter_bit, 2)]
    return ot1

def find_collision():
    hashed_passwords = {}
    collision = False
    iteration = 0
    while not collision:
        print(iteration)
        iteration +=1
        ot0 = ''.join(random.choice(ALPHABET) for i in range(6))
        box = SHA1.new(bytes(ot0, "UTF-8"))
        h = bin(int(box.hexdigest(), 16))[2:].zfill(128)[:36]
        ot1 = ""
        for i in range(6):
            letter_bit = h[6 * i:6 * (i + 1)]
            ot1 += ALPHABET[int(letter_bit, 2)]
        if ot1 in hashed_passwords:
            collision = True
            print(f"collision on {ot0} and {ot1}")
        else:
            hashed_passwords[ot1] = ot0



if __name__ == "__main__":
    ot0 = initialize()
    ans = "y"
    while(ans == "y"):
        ot = generate_password(ot0)
        ot0 = ot
        print(f"Your password: {ot}")
        print("Do you want to generate new? y/n")
        try:
            ans = input().lower()[0]
        except IndexError:
            ans = ""

    find_collision()



