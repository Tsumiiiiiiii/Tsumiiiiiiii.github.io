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
K = p2 ^ c2$$
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
Flag: **uiuctf{burn_3ach_k3y_aft3r_us1ng_1t}**

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
Flag: **uiuctf{W3_hav3_R5A_@_h0m3}**

## Group project

{{< admonition note "Challenge Information" >}}
* **Points:** 50
* **Description:** In any good project, you split the work into smaller tasks...

`nc group.chal.uiuc.tf 1337`

Artifacts are [chal.py](https://2023.uiuc.tf/files/9e2a52e6e934a0de1bb0e5502c5010a5/chal.py)
{{< /admonition >}}

Let's have a look on the source code, we are gven a classic implementation of diffie hellman cryptosystem.
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
$$Bk = B ^ 0 \mod\ p \equiv\ 1 \mod\ p$$
$$S = 1 ^ a \mod\ p \equiv\ 1 \mod\ p$$

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
Flag: **uiuctf{brut3f0rc3_a1n't_s0_b4d_aft3r_all!!11!!}**

## Group projection

{{< admonition note "Challenge Information" >}}
* **Points:** 50
* **Description:** I gave you an easier project last time. This one is sure to break your grade!

`nc group-projection.chal.uiuc.tf 1337`

Artifacts are [chal.py] https://2023.uiuc.tf/files/57e4b21396687f7959ef3ee1b5264138/chal.py)
{{< /admonition >}}

Almost the same problem as before, but with some extra constraints.
```python
if k == 1 or k == p - 1 or k == (p - 1) // 2 or k <= 0 or k >= p:
        print("[$] I'm not that dumb...")
        return
```
We can't set `k = 0` anymore. What can we do then? Is there a way to force `S` to be 1 like before?

Since `p` is a prime, we could have set `k = p - 1` and `S` would have been 1.
