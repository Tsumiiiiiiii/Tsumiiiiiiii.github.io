---
weight: 1
title: "HTB UNI CTF 2023 - MSS and RMSS Writeups"
date: 2023-12-28T02:05:00+06:00
lastmod: 2023-12-28T02:05:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for the MSS Cryptography challenge."

tags: ["crypto", "secret-sharing", "polynomials", "HTB CTF", "english"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---

Writeup for the MSS Cryptography challenge.


## MSS

The script we are provided with is:

```python
import os, random, json
from hashlib import sha256
from Crypto.Util.number import bytes_to_long
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secret import FLAG


class MSS:
    def __init__(self, BITS, d, n):
        self.d = d
        self.n = n
        self.BITS = BITS
        self.key = bytes_to_long(os.urandom(BITS//8))
        self.coeffs = [self.key] + [bytes_to_long(os.urandom(self.BITS//8)) for _ in range(self.d)]

    def poly(self, x):
        return sum([self.coeffs[i] * x**i for i in range(self.d+1)])

    def get_share(self, x):
        if x > 2**15:
            return {'approved': 'False', 'reason': 'This scheme is intended for less users.'}
        elif self.n < 1:
            return {'approved': 'False', 'reason': 'Enough shares for today.'}
        else:
            self.n -= 1
            return {'approved': 'True', 'x': x, 'y': self.poly(x)}
    
    def encrypt_flag(self, m):
        key = sha256(str(self.key).encode()).digest()
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(m, 16))
        return {'iv': iv.hex(), 'enc_flag': ct.hex()}

def show_banner():
    print("""
#     #  #####   #####               #       ###   
##   ## #     # #     #             ##      #   #  
# # # # #       #                  # #     #     # 
#  #  #  #####   #####     #    #    #     #     # 
#     #       #       #    #    #    #     #     # 
#     # #     # #     #     #  #     #   ## #   #  
#     #  #####   #####       ##    ##### ##  ###

This is a secure secret sharing scheme with really small threshold. We are pretty sure the key is secure...
    """)

def show_menu():
    return """
Send in JSON format any of the following commands.

    - Get your share
    - Encrypt flag
    - Exit

query = """


def main():
    mss = MSS(256, 30, 19)
    show_banner()
    while True:
        try:
            query = json.loads(input(show_menu()))
            if 'command' in query:
                cmd = query['command']
                if cmd == 'get_share':
                    if 'x' in query:
                        x = int(query['x'])
                        share = mss.get_share(x)
                        print(json.dumps(share))
                    else:
                        print('\n[-] Please send your user ID.')
                elif cmd == 'encrypt_flag':
                    enc_flag = mss.encrypt_flag(FLAG)
                    print(f'\n[+] Here is your encrypted flag : {json.dumps(enc_flag)}.')
                elif cmd == 'exit':
                    print('\n[+] Thank you for using our service. Bye! :)')
                    break
                else:
                    print('\n[-] Unknown command:(')
        except KeyboardInterrupt:
            exit(0)
        except (ValueError, TypeError) as error:
            print(error)
            print('\n[-] Make sure your JSON query is properly formatted.')
            pass

if __name__ == '__main__':
    main()

```

What happens here is that, we have a $key$ that is encrypted with a polynomial:

$$ y = key + c_1 * x + c_2 * x^2 + c_3 * x^3 + \ldots + c_{d-1} * x^{d-1} + c_d * x^d$$

Here $c_1, c_2, \ldots, c_d$ are coefficients that  are randomly generated and is not revealed to the user, not to mention that the $key$ is kept hidden as well. We can provide a value of our choice $x$ provided that $x < 2^{15}$. For this particular problem, there was no lower limit for the value of $x$ (which caused it to have a very easy unintended solution). We can just provide $x = 0$ and what we are going to get in return is:

$$ y = key + c_1 * 0 + c_2 *0^2 + \ldots+ c_d * 0^d$$ 

$$\rightarrow y = key$$

We are returned the secret, and we can use it to get the AES key and decrypt the flag.

## MSS Revenge

This is basically the same problem as before with the difference being the restriction on the lower bound on $x$, which forced us to use the intended solve. The difference in the script is in this following line:

```python
def get_share(self, x):
    if x < 1 or x > 2**15:
        return {'approved': 'False', 'reason': 'This scheme is intended for less users.'}

```

The limit is thus : $1 < x < 2^{15}$. Because of this, our previous solution of $x=0$ won't work anymore. What happens if we send a random prime $p$, and for the returned value $y$, we mod that with $p$ as well?

$$ y \equiv key + c_1 * p + c_2 *p^2 + \ldots+ c_d * p^d \mod p$$

$$\rightarrow y \equiv key \mod p $$

Now, we notice the $key$ is of 256 bits($key <= 2^{256}$). So if we can send a prime $p$ where $p > 2^{256}$, we would get the secret, unbothered my the modulo operation. But the problem here is that we are restricted to $p < 2^{15}$. For any such $p$, we are going to get a reduced version of $key$. 

`chinese remainder theorem` comes to the rescue here. The question is, what should be the length of primes $p_i$ and how many queries do we need. From the script it is clear that we are able to send a maximum of 19 queries. What should be the size of each of those 19 primes then? As per the principle of `crt`, we need the product of those 19 primes to be bigger than that of the size of $key$, so that the following holds:

$$ key \mod (p_1 \ * p_2 \ * \ldots * \ p_{19} ) = key $$

$$ \rightarrow key < (p_1 \ * p_2 \ * \ldots * \ p_{19} )  $$

$$ \rightarrow size_{key} < size_{primesProduct} $$

$$ \rightarrow 256 < 19 * sz $$

The above holds for $sz=14$. So, each of our 19 primes should have a length of 14 bits ($<2^{14}$). This is in the allowed range!  We send those 19 primes($p_1, p_2, \ldots, p_{19}$) and in return get $y_1, y_2, \ldots, y_{19}$. Using that we can apply `crt` and recover the original `key`.

```python

import os, random, json
from hashlib import sha256
from Crypto.Util.number import bytes_to_long, getPrime
from Crypto.Cipher import AES

def decrypt(iv, ct, key):
  key = sha256(str(key).encode()).digest()
  cipher = AES.new(key, AES.MODE_CBC, iv)
  ret = cipher.decrypt(ct)
  return ret

while True:
  mods = [getPrime(14) for _ in range(40)]
  mods = list(set(mods))
  if len(mods) >= 20: break

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('94.237.60.78', 38549))

vals = []
mods = mods[:19]
for p in mods:
  recvuntil(sock, b'query = ')
  d = {"command":"get_share", "x" : str(p)}
  d = json.dumps(d)
  sendline(sock, d.encode())
  r = json.loads(recvline(sock).decode())
  vals.append(int(r['y']) % p)
  
print(vals)
recvuntil(sock, b'query = ')
d = {"command":"encrypt_flag"}
d = json.dumps(d)
sendline(sock, d.encode())
recvuntil(sock, b'flag : ')
r = recvline(sock).decode().strip().replace(' ', '').replace('.', '')

print(r)

r = json.loads(r)
iv = r['iv']
ct = r['enc_flag']

key = crt(mods, vals)[0]
decrypt( bytes.fromhex(iv), bytes.fromhex(ct), key)
```

This gets us the following output:

```bash
[3454, 12232, 6987, 8852, 6678, 2372, 5777, 555, 1571, 920, 2134, 5566, 7939, 3620, 12113, 14328, 1944, 10612, 2717]
{"iv":"69d5adf7969cffdaf349ea98d7fd1f30","enc_flag":"ac147c90ab5bd2eaa9e4bc6313638303884fda15114b988775412b919efb891bd2642f47a605a4acb20c7e1bb429bd3d"}

b'HTB{R3venge_0f_7he_sm4ll_thr3sh0ld_!}\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
```

