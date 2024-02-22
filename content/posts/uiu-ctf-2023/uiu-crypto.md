---
weight: 1
title: "UIU CTF 2023 - Cryptography Writeups"
date: 2023-07-03T11:02:00+06:00
lastmod: 2023-07-03T11:02:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for the Cryptography challenges."

tags: ["crypto", "UIU CTF", "english"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---

Writeup for the Cryptography challenges.

<!--more-->

## Overview
UIU CTF ended just a few hours back. This year's Crypto was easier than last year's. But it was very fun to solve, especially `group projection` and `morphing time`. I managed to solve 5/6 problems. Failed to solve `crack-the-safe` because I had some mistakes in my formulas, and also because I could not make Cado run on my pc 🤡. Anyways, here are the writeups of the challenges I solved. 

## Three-Time Pad

{{< admonition note "Challenge Information" >}}
* **Points:** 50
* **Description:** "We've been monitoring our adversaries' communication channels, but they encrypt their data with XOR one-time pads! However, we hear rumors that they're reusing the pads...
Enclosed are three encrypted messages. Our mole overheard the plaintext of message 2. Given this information, can you break the enemy's encryption and get the plaintext of the other messages?"

Artifacts are [c1](https://2023.uiuc.tf/files/4daf6f657250c79cf8d500fc16d805d7/c1), [c2](https://2023.uiuc.tf/files/dd3dbe6e45aa09480fbc794f4ff26936/c2), [c3](https://2023.uiuc.tf/files/e0010beea1f7483e72631e4ea6e927bd/c3), [p2](https://2023.uiuc.tf/files/3d2d3993dbc39c9ee16b927f9e5ac6fc/p2).
{{< /admonition >}}

Simple XOR challenge. We are given 3 encrypted files `c1, c2, c3` all encrypted with the same key `K`. The original second file `p2` has been given too. 
So it's trivial to retrieve the key now.
```
K = p2 ^ c2
p1 = K ^ c1
p3 = K ^ c3
```

Then we check which of `p1` or `p3` contains the flag and we see that `p3` indeed has the flag.

```python
from pwn import *

with open('c1' ,'rb') as f:
    c1 = f.read()

with open('c2' ,'rb') as f:
    c2 = f.read()

with open('c3' ,'rb') as f:
    c3 = f.read()

with open('p2' ,'rb') as f:
    p2 = f.read()

key = xor(c2, p2)
m1 = xor(c1, key)
m2 = xor(c3, key)
print(m1)
print(m2)
```
> Flag: **uiuctf{burn_3ach_k3y_aft3r_us1ng_1t}**

---

## At Home

{{< admonition note "Challenge Information" >}}
* **Points:** 50
* **Description:** Mom said we had food at home

Artifacts are [chal.py](https://2023.uiuc.tf/files/0d49da3310c51c11923c260798245076/chal.py) and [chal.txt](https://2023.uiuc.tf/files/da5c55d203a146d0a5e7d8b5137172b7/chal.txt)
{{< /admonition >}}

From the source code, it can be seen that,
$$c = flag*e\mod\ n$$

We can just re-write the equation as, 
$$flag = c*e^{-1}\mod\ n $$

Since we are given all the parameters, `c, e, n`, it's trivial to retrieve the flag.

```python
from Crypto.Util.number import long_to_bytes as l2b
flag  = (c * pow(e, -1, n)) % n
flag = l2b(flag)
```
> Flag: **uiuctf{W3_hav3_R5A_@_h0m3}**

---

## Group project

{{< admonition note "Challenge Information" >}}
* **Points:** 50
* **Description:** In any good project, you split the work into smaller tasks...

`nc group.chal.uiuc.tf 1337`

Artifacts are [chal.py](https://2023.uiuc.tf/files/9e2a52e6e934a0de1bb0e5502c5010a5/chal.py)
{{< /admonition >}}

Let's have a look at the source code, we are given a classic implementation of **diffie hellman cryptosystem**.
```python
def main():
    print("[$] Did no one ever tell you to mind your own business??")

    g, p = 2, getPrime(1024)
    a = randint(2, p - 1)
    A = pow(g, a, p)
    print("[$] Public:")
    print(f"[$]     {g = }")
    print(f"[$]     {p = }")
    print(f"[$]     {A = }")

    try:
        k = int(input("[$] Choose k = "))
    except:
        print("[$] I said a number...")

    if k == 1 or k == p - 1 or k == (p - 1) // 2:
        print("[$] I'm not that dumb...")

    Ak = pow(A, k, p)
    b = randint(2, p - 1)
    B = pow(g, b, p)
    Bk = pow(B, k, p)
    S = pow(Bk, a, p)

    key = hashlib.md5(long_to_bytes(S)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    c = int.from_bytes(cipher.encrypt(pad(flag, 16)), "big")

    print("[$] Ciphertext using shared 'secret' ;)")
    print(f"[$]     {c = }")
```
We have to provide such a value of `k`, for which we know the value of `S`. 

What happens if `k = 0` ? Let's see the math

$$
\begin{aligned}
Bk & \equiv B ^ 0  & \equiv 1 & \mod p \\\\
S & \equiv 1 ^ a   & \equiv 1 & \mod p
\end{aligned}
$$

So we now know `S`. From here on it's trivial to recover the key and hence get the flag.

```python
from Crypto.Util.number import getPrime, long_to_bytes
from random import randint
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwn import *

io = remote('group.chal.uiuc.tf', 1337)

key = hashlib.md5(long_to_bytes(1)).digest()
cipher = AES.new(key, AES.MODE_ECB)

io.recvuntil(b'??')
io.recvline()
io.recvline()

g = int(io.recvline().decode().strip().split('=')[1])
p = int(io.recvline().decode().strip().split('=')[1])
A = int(io.recvline().decode().strip().split('=')[1])

io.recvuntil(b'= ')
io.sendline(b'0')
io.recvuntil(b'= ')
enc = int(io.recvline().decode().strip())
flag = cipher.decrypt(long_to_bytes(enc))
print(flag)
```
> Flag: **uiuctf{brut3f0rc3_a1n't_s0_b4d_aft3r_all!!11!!}**

---

## Group projection

{{< admonition note "Challenge Information" >}}
* **Points:** 50
* **Description:** I gave you an easier project last time. This one is sure to break your grade!

`nc group-projection.chal.uiuc.tf 1337`

Artifacts are [chal.py](https://2023.uiuc.tf/files/57e4b21396687f7959ef3ee1b5264138/chal.py)
{{< /admonition >}}

Almost the same problem as before, but with some extra constraints.
```python
if k == 1 or k == p - 1 or k == (p - 1) // 2 or k <= 0 or k >= p:
        print("[$] I'm not that dumb...")
        return
```
We can't set `k = 0` anymore. What can we do then? Is there a way to force `S` to be 1 like before?

Since `p` is a prime, we could have set `k = p - 1` and `S` would have been 1, due to Fermat's little theorem.

$$
\begin{aligned}
Bk & \equiv B^{p-1} & \equiv 1 \mod p \\\
S & \equiv 1 ^ a & \equiv 1 \mod p
\end{aligned}
$$ 

But we can't set `k = p - 1` due to constraints, sadly. What if we send `k =  (p - 1) / 4` instead?

Now, when such a case comes so that $p - 1 \mod\ 4 \equiv\ 0$ and also $a*b \mod\ 4 \equiv\ 0$, what happens?

Since `a*b` is a multiple of 4, we can write it as $a * b = 4*i$ for some integer `i`.

$$
\begin{aligned}
S & \equiv\ g^{a * b * k} & \mod p \\\
S & \equiv\ g^{4i * \frac{p-1}{4}} & \mod p \\\
S & \equiv\ ({g^{p-1}})^i & \mod p \\\
S & \equiv\ 1^i \equiv\ 1 & \mod p
\end{aligned}
$$

Yep, the math adds up and we have `S = 1`.

We keep running the instance until the required conditions are fulfilled, and once we get such an instance, we can decrypt the flag.
```python
from Crypto.Util.number import getPrime, long_to_bytes
from random import randint
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from pwn import *

def attempt():
    io = remote('group-projection.chal.uiuc.tf', 1337)

    key = hashlib.md5(long_to_bytes(1)).digest()
    cipher = AES.new(key, AES.MODE_ECB)

    io.recvuntil(b'??')
    io.recvline()
    io.recvline()

    g = int(io.recvline().decode().strip().split('=')[1])
    p = int(io.recvline().decode().strip().split('=')[1])
    A = int(io.recvline().decode().strip().split('=')[1])

    if (p - 1) % 4 != 0:
        return True
    
    print('Maybe???')

    k = (p - 1) // 4

    io.recvuntil(b'= ')
    io.sendline(str(k).encode())
    io.recvuntil(b'= ')
    enc = int(io.recvline().decode().strip())
    flag = cipher.decrypt(long_to_bytes(enc))
    if b"uiuctf" in flag:
        print(flag)
        return False
    else:
        print('Oh no!!')
        return True

while attempt():
    continue
```

After running around a minute or so, we get the flag.

> Flag: **uiuctf{brut3f0rc3_w0rk3d_b3f0r3_but_n0t_n0w!!11!!!}**

---

## Morphing Time

{{< admonition note "Challenge Information" >}}
* **Points:** 50
* **Description:** The all revealing Oracle may be revealing a little too much...

`nc morphing.chal.uiuc.tf 1337`

Artifacts are [chal.py](https://2023.uiuc.tf/files/1f2fbbc0bc1392a6bfb48ed876885324/chal.py)
{{< /admonition >}}

Let's go through the given script
```python
def setup():
    # Get group prime + generator
    p = getPrime(512)
    g = 2

    return g, p


def key(g, p):
    # generate key info
    a = randint(2, p - 1)
    A = pow(g, a, p)

    return a, A


def encrypt_setup(p, g, A):
    def encrypt(m):
        k = randint(2, p - 1)
        c1 = pow(g, k, p)
        c2 = pow(A, k, p)
        c2 = (m * c2) % p

        return c1, c2

    return encrypt


def decrypt_setup(a, p):
    def decrypt(c1, c2):
        m = pow(c1, a, p)
        m = pow(m, -1, p)
        m = (c2 * m) % p

        return m

    return decrypt


def main():
    print("[$] Welcome to Morphing Time")

    g, p = 2, getPrime(512)
    a = randint(2, p - 1)
    A = pow(g, a, p)
    decrypt = decrypt_setup(a, p)
    encrypt = encrypt_setup(p, g, A)
    print("[$] Public:")
    print(f"[$]     {g = }")
    print(f"[$]     {p = }")
    print(f"[$]     {A = }")

    c1, c2 = encrypt(flag)
    print("[$] Eavesdropped Message:")
    print(f"[$]     {c1 = }")
    print(f"[$]     {c2 = }")

    print("[$] Give A Ciphertext (c1_, c2_) to the Oracle:")
    try:
        c1_ = input("[$]     c1_ = ")
        c1_ = int(c1_)
        assert 1 < c1_ < p - 1

        c2_ = input("[$]     c2_ = ")
        c2_ = int(c2_)
        assert 1 < c2_ < p - 1
    except:
        print("!! You've Lost Your Chance !!")
        exit(1)

    print("[$] Decryption of You-Know-What:")
    m = decrypt((c1 * c1_) % p, (c2 * c2_) % p)
    print(f"[$]     {m = }")

    # !! NOTE !!
    # Convert your final result to plaintext using
    # long_to_bytes

    exit(0)
```

This is the **Elgamal Cryptosystem**, which is **homomorphic** under multiplication. We have,

$$
\begin{align}
c_1 & = g^k & \mod p \\\
c_2 & = g^{ak} * m & \mod p
\end{align}
$$

To take advantage of the homomorphic property, we send `c1_ = c1` and `c2_ = c2`.

So now we have,

$$
\begin{aligned}
c_1 & = g^{2k} & \mod p \\\
c_2 & = g^{2ak} * m^2 & \mod p
\end{aligned}
$$

And they decrypt to,
$$({c_1 ^ a}) ^ {-1} * c_2  \equiv\ g^{-2ak} * g^{2ak} * m^2 \equiv\ m^2 \mod p$$

This gives us the flag squared modulo p. To retrieve the flag, we can use **tonelli shanks** algorithm.

But the problem is, the result does not decrypt to a valid string. This made me think that maybe `flag > p`, and that's why we are losing information.

As a fix, we can run the instance multiple times, collect the square root and modulus pairs and run **CRT** on each of those pairs to see which gives us the flag.
```python
from Crypto.Util.number import long_to_bytes
from sympy.ntheory.modular import crt
from pwn import *

def legendre(a, p):
    return pow(a, (p - 1) // 2, p)

def tonelli(n, p):
    assert legendre(n, p) == 1, "not a square (mod p)"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r


def get_params():
    io = remote('morphing.chal.uiuc.tf', 1337)
    io.recvuntil(b'Public:\n')

    g = int(io.recvline().decode().strip().split('=')[1])
    p = int(io.recvline().decode().strip().split('=')[1])
    A = int(io.recvline().decode().strip().split('=')[1])

    io.recvline()
    c1 = int(io.recvline().decode().strip().split('=')[1])
    c2 = int(io.recvline().decode().strip().split('=')[1])

    io.recvline()
    io.recvuntil(b'= ')
    io.sendline(str(c1).encode())
    io.recvuntil(b'= ')
    io.sendline(str(c2).encode())

    io.recvline()
    m = int(io.recvline().decode().strip().split('=')[1])

    return p, m

mods = []
vals = []

for i in range(10):
  p, m = get_params()
  res = tonelli(m, p)
  mods.append(p)
  vals.append(res)

sz = len(mods)

print('Will start doing the CRTS')

for i in range(sz - 1):
    for j in range(i + 1, sz):
        ans = long_to_bytes(crt([mods[i], mods[j]], [vals[i], vals[j]])[0])
        if b'uiuctf' in ans:
            print(ans)
            exit(2)
```
> Flag: **uiuctf{h0m0m0rpi5sms_ar3_v3ry_fun!!11!!11!!}**
