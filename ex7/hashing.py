import hashlib

txtfile = open("C://Users/Karol/Documents/hashfile.txt", "w")
txtfile.write(hashlib.md5(b"3212").hexdigest() + "\n")
txtfile.write(hashlib.md5(b"star_2").hexdigest() + "\n")
txtfile.write(hashlib.md5(b"karolwes").hexdigest() + "\n")
txtfile.write(hashlib.md5(b"test").hexdigest() + "\n")
txtfile.write(hashlib.md5(b"3mpty_passw0rd").hexdigest() + "\n")
txtfile.write(hashlib.md5(b"v4AgaZ4K").hexdigest() + "\n")
txtfile.write(hashlib.md5(b"7yhYAQKt1MpH#1e7Mu").hexdigest() + "\n")

txtfile.close()