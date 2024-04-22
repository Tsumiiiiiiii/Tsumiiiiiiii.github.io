---
weight: 1
title: "iutCTF 2024 easy-medium crypto writeups"
date: 2024-04-21T00:37:00+06:00
lastmod: 2024-04-21T00:37:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for my easy-medium Cryptography challenges from iutCTF24."

tags: ["crypto", "iutCTF", "cow", "esolang", "RSA", "nonce-reuse", "hash", "merkle-tree", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true

toc:
  enable: true
---

Writeup for some Cryptography challenges from LA CTF 24.


<!--more-->



# Cow

There is an esolang called **Cow**. Any online decoder will work.

> **iutctf{__wh0_l3t_th3_c0w_0u7_M0o_mo0_m00_moo_M00__}**

---
# ps3

```python
from hashlib import md5
from Crypto.Util.number import getPrime
from random import randint

def getParams():
    q = getPrime(512)
    k = randint(1, q - 1)
    g = randint(1, q - 1)
    r = pow(g, k, q)
    return q, k, r

def sign(m, q, k, r, d):
    h = int(md5(m.encode()).hexdigest(), 16)
    s = (h + r * d) % q
    s = (s * pow(k, -1, q)) % q
    return s

q, k, r = getParams()
d = int(open('flag.txt', 'rb').read().hex(), 16)

s1 = sign('play_station_three', q, k, r, d)
s2 = sign('jail_break', q, k, r, d)

with open('out.txt', 'w') as f:
    f.write(f'q = {q}\n')
    f.write(f'r = {r}\n')
    f.write(f's1 = {s1}\n')
    f.write(f's2 = {s2}')
```

This problem deals with a very classic attack in cryptography : the **nonce reuse attack in Digital Signatures**. 

Some parameters $q, k, g, r$ is generated initially which will be later used to signed any value. Here $r = g^k \mod q$ but this relation is not important for the underlying challenge. 

Now let us see how a value is signed and the value $s$ is derived.

$$
s = \frac{\text{H}(m) + r*d}{k} \mod q
$$

Here $d$ is the private key and $k$ is the nonce. The hash $\text{H}(m)$ is known and so is $s, q$. 

## Understanding the attack

Suppose we are going to sign two different messages $m_1, m_2$. The intended way is to generate a different $k$ for each signing. It is called a nonce(_n_once_) after all. The problem occurs when we use $k$ to sign both messages, and this is exactly what happens in this particular problem. That is,


$$\begin{aligned} s\_1 &= \frac{\text{H}(m_1) + r\*d}{k} \mod q \\\\ s_2 &= \frac{\text{H}(m_2) + r*d}{k} \mod q \end{aligned}$$


From the first equation we can write, $s_1 * k = \text{H}(m_1) + r\*d$ and from the second equation we can write $s_2 * k = \text{H}(m_2) + r*d$. Subtracting them gives us

$$k = \frac{\text{H}(m_1) - \text{H}(m_2)}{s_1 - s_2} \mod q$$

We have recovered the super secret nonce! And once we have $k$, we can recover the private key $d$ using

$$
d = \frac{s*k - \text{H}(m)}{r} \mod q
$$

```python
from hashlib import md5

h1 = int(md5(b'play_station_three').hexdigest(), 16)
h2 = int(md5(b'jail_break').hexdigest(), 16)

with open('out.txt', 'r') as f:
    exec(f.read())

l = ((h1 - h2 + q) * s2 * pow(s1-s2 + q, -1, q)) % q
l = (l - h2 + q) % q
d = (l * pow(r, -1, q)) % q
flag = d.to_bytes(512//8, 'big')
print(flag)
```

> **iutctf{__1_533_th4t_y0u_h4v3_m4st3r3d_7h3_inf4m0us_PS3_4774Ck__}**

---

# Incorrect RSA

```python
from Crypto.Util.number import getPrime, bytes_to_long as b2l

with open('flag.txt', 'rb') as f:
    flag = f.read()

assert (len(flag) == 28)

p = getPrime(2048)
e = 16588

flag = b2l(flag)
ct = pow(flag, e, p)

with open('out.txt', 'w') as f:
    f.write(f'p = {p}\n')
    f.write(f'ct = {ct}')
```

The reason this problem was set is to test the root level understanding of RSA. A lot of people simply use online tools or pre-found templates to decrypt RSA without understanding the underlying mathematics. A requirement for the public key $e$ is that $\text{GCD}(e,\  phi) = 1$. $phi$ is always even by definition since we always use odd primes only. This means $e$ must be even, or else there will be a bigger GCD and then we can't derive a private key $d$. 

In the given problem, we have $e = 2^2 * 11 * 13 * 29$. And so the GCD with $phi$ will not be $1$. For this reason we can't calculate $d = e^{-1} \mod phi$. Trying to do so will give error.  

Instead of working with $d$, we are going to find $d' = e' ^{-1} \mod q$ where $e' = e / 4 = 11\*13*29$. 

$$
\begin{aligned}
c^{d'} &= (m^e)^{d'} &\mod n \\\
&= (m^{2^2 * 11 * 13 * 29})^{\frac{1}{11 * 13 * 29}} &\mod n \\\
&= m^{\frac{2^2 * 11 * 13 * 29}{11 * 13 * 29}} &\mod n \\\
&= m^4 &\mod n
\end{aligned}
$$

Now we have $m^4$ but our goal is to find $m$. Notice the script says that the flag $m$ has a length of 28. In terms of bits, there will be a maximum of $28 * 8=224$ bits. But the modulus $n$ is $2048$ bits. Guess what that means? $m^4$ is $224 * 4 = 896$ bits. That is, $m^4 < n$. So $m^4 \mod n$ and $m^4$ is simply the same thing as the effect of modulo by $n$ can be ignored now. Hence $c^{d'}$ is simply $m^4$. The mod is omitted. We  can take square root twice or the $4th$ root to find $m = \sqrt[4]{c^{d'}}$.    

```python
from Crypto.Util.number import long_to_bytes as l2b
from gmpy2 import iroot

p = 19...61
ct = 53...09

e = 16588
d = pow(e // 4, -1, p - 1)
m_ = pow(ct, d, p)
m, _ = iroot(m_, 4)
m = l2b(m)
print(m)
```

> **iutctf{0h_n0_50m30n3_Go7_1t}**

---


## Hypocrite Tree

```python
#!/usr/local/bin/python

from hashlib import sha256
import os

def get_blocks(s):
    blocks = []
    for i in range(0, len(s), 8):
        blocks.append(s[i : i + 8])
    return blocks

class HTREE:
    def __init__(self, s):
        self.blocks = get_blocks(s)

    def COMBINE(self, LH, RH):
        if int(LH.hex(), 16) > int(RH.hex(), 16):
            LH, RH = RH, LH
        return sha256(LH + RH).digest()
    
    def HASH(self, L, R):
        if L == R:
            return sha256(self.blocks[L]).digest()
        else:
            M = (L + R) // 2
            LH = self.HASH(L, M)
            RH = self.HASH(M + 1, R)
            return self.COMBINE(LH, RH)
        
    def GET(self):
        return self.HASH(0, len(self.blocks) - 1)
        

print('Welcome to the Hypocrite Tree. Show your different faces and pretend to be the same persona to get the flag!')

s = os.urandom(128)
T = HTREE(s)
h = T.GET()

seen = set()
seen.add(sha256(s).digest())

print(f'For the string {s.hex()}, the hypocrite hash is {h.hex()}')

for rounds in range(1, 256):
    s = bytes.fromhex(input('Enter your new face: '))
    assert len(s) == 128, "Make sure the string is of the correct length"
    assert sha256(s).digest() not in seen, "Too honest for the flag -_-"

    h_ = HTREE(s).GET()
    assert h == h_, "Too dumb for the flag -_-"
    print('Thats my lovely hypocrite boy!')

with open('flag.txt', 'r') as f:
    print(f.read())
```

The `HTREE` class is a merkle tree-like data structure that operates on hashes. It
divides the given message into blocks of size $8$ ($B_1, B_2, \cdots, B_n$) and combines them in a way after the blocks are hashed.

$$
\text{HASH}(B\_l, \cdots,  B\_{r}) = 
\begin{cases}
\begin{aligned}
&\text{SHA256}(B\_l) &&\ \ \ if \ \  l=r \\\
&\text{COMBINE}(\text{HASH}(B\_l, \cdots, B\_{\frac{l + r}{2}}), \ \text{HASH}(B\_{\frac{l + r}{2} + 1}, \cdots, B\_r)) &&\ \ \  else
\end{aligned}
\end{cases}
$$

$$
\text{COMBINE}(B_1, B_2) =
\begin{cases}
\begin{aligned}
\text{H}(\text{H}(B_1) + \text{H}(B_2)) &\ \ \ if \ \ \text{H}(B_1) < \text{H}(B_2) \\\
\text{H}(\text{H}(B_2) + \text{H}(B_1)) &\ \ \ else
\end{aligned}
\end{cases}
$$

In the `COMBINE` function $+$ sign denotes "concatenation".  We are tasked with forging hashes. That is, we are given $M$ and $\text{HASH}(M)$ where our job is to find another different message $M'$ such that $\text{HASH}(M) = \text{HASH}(M')$. To be specific we need to find 256 different messages with the same hash, but for simplicity let us assume we need to find just one more message. 

The trick is to realize that if we have a message $M$ of length 16 which is divided into two blocks $B_1, B_2$, that is, $M = B_1 + B_2$, then another message $M' = B_2 + B_1$ will give the exact same hash. This is because if the latter block had a bigger hash, then the `COMBINE` function would simply swap it with the first block and then hash them.  

<img src="https://github.com/Tsumiiiiiiii/Tsumiiiiiiii.github.io/blob/main/content/posts/iutCTF24/g0.svg?raw=true"/>
 

The two trees above denote the same hash. In fact, this holds for any message, we can simply swap their block order and they will give the same hash. As there are 2 blocks in a message of length $16$, and we can only derive 2 different permutations of the blocks, we can hence derive 2 different messages that result in the same hash.

How many different messages could we generate if we instead had a message of length $32$ ($4$ blocks)?  $M = B_1 + B_2 + B_3 + B_4$.  For each pair of consecutive block, we can swap their order. We have here 2 block pairs. We can choose to either swap a block pair or leave it unchanged. Hence we have $2^2 = 4$ choices in total. That means, we can have $4$ different messages that produce the same hash. 

<img src="https://github.com/Tsumiiiiiiii/Tsumiiiiiiii.github.io/blob/main/content/posts/iutCTF24/g3.svg?raw=true"/>

The 4 trees above shows the block ordering possible. Blue edges indicate the consequent pair has been swapped. 

In this way, for a message with a block length of $2n$ we have $n$ pairs and a total of $2^n$ orderings that will give the same hash. For the given challenge, the message length is $128$, which means we have $128/8 = 16$ blocks or $8$ block pairs. So we can generated a total of $2^8=256$ different messages that has the same hash.

```python
from tqdm import tqdm

io = ProcessWrapper(['python', '/content/server.py'])

io.recvline()
l = io.recvline().strip().split()
s, h = bytes.fromhex(l[3].replace(',', '')), l[-1]


def get_blocks(s):
  blocks = []
  for i in range(0, len(s), 8):
      blocks.append(s[i: i + 8])
  return blocks


def make_pairs(blocks):
  pairs = []
  for i in range(0, len(blocks), 2):
    pairs.append([blocks[i], blocks[i + 1]])
  return pairs


pairs = make_pairs(get_blocks(s))
n = len(pairs)

for mask in tqdm(range(1, 1 << n)):
  to_send = b''
  for i, pair in enumerate(pairs):
    if (mask & (1 << i)):
      to_send += pair[1]
      to_send += pair[0]
    else:
      to_send += pair[0]
      to_send += pair[1]

  io.recvuntil(': ')
  io.sendline(to_send.hex())

for _ in range(5):
  print(io.recvline())
```

> **iutctf{__4n0th3r_hyp0Cr173_Ju57_LiK3_M3_1_533_HeHe_o_0__}**

