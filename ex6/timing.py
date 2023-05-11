import random
import string

# O(len(secret)+1)
def guess_len():
    l = 0
    time = exec_time = 0
    while exec_time >= time:
        time = exec_time
        l+=1
        ans = 'a'*l
        _, exec_time = match(ans)
    return l-1


# O(alphabet_size*len(secret)) ~~ O(n)
def recover_string(l):
    s = 'a'* l
    for m in range(l):
        time = 0
        i = 0
        _, exec_time = match(s)
        while exec_time >= time:
            time = exec_time
            i+=1
            new_let = chr(ord('a')+i)
            s = s[:m] + new_let + s[m+1:]
            _, exec_time = match(s)
        new_let = chr(ord('a') + i-1)
        s = s[:m] + new_let + s[m + 1:]
    return s


# O(len(secret))
def match(guess):
    elapsed_time = 0
    match_value = True
    elapsed_time = elapsed_time + 1
    if len(secret) != len(guess):
        match_value = False
        elapsed_time = elapsed_time + 5
    if match_value:
        for i in range(len(secret)):
            elapsed_time = elapsed_time + 10
            if secret[i] != guess[i]:
                match_value = False
                return match_value, elapsed_time
        elapsed_time = elapsed_time + 10
    return match_value, elapsed_time

if __name__ == "__main__":
    max_len = 100  # Max length of password
    pwd_len = random.randrange(3, max_len + 1)
    secret = ''.join(random.choice(string.ascii_lowercase) for i in range(pwd_len))
    guess = "blabla"
    [iscorrect, time] = match(guess)
    print(f"Secret is {secret}, guessed is {guess}, match function says {iscorrect}, and took {time} time.")
    print(f"secret is: {recover_string(guess_len())}")

