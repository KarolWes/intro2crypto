e = 17
p = 37
q=p
n = p*q
fi = (p-1)*(q-1)
d = 1
while (d*e-1)%fi != 0:
    d+=1
    print('+', end="")
print("")
print(d)