---
weight: 1
title: "BUET CTF 2026 Finals - Writeups for my authored crypto challenge (Yet Another RNG)"
date: 2026-01-31T00:30:00+06:00
lastmod: 2026-01-31T00:30:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: ""

tags: ["crypto", "BUETCTF", "math", "dlog", "HNP", "randcrack", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true

---

<!--more-->

Yet another BUET CTF, yet another very nicely organized CTF. Many thanks to the organizers for the opportunity.

That said, I wrote $2$ problems for the qualifying round, both of them being crypto, and both got slopped by AI. For the finals, I wrote only a single challenge, which ended up with a single solve,
and turned out to be the title decider problem. This write-up will be a brief sketch on how to solve that challenge.

## Overview

We are provided with a compact script (< 50 lines)

```python
#!/usr/local/bin/python
import random
from Crypto.Util.number import isPrime, bytes_to_long
from hashlib import sha256
import os

flag = open('flag.txt', 'rb').read()
assert len(flag) == 36

class RNG:
    def __init__(self, p, g, seed):
        self.p = p
        self.g = g
        random.seed(seed)

    def sample(self):
        return pow(self.g, random.getrandbits(245), self.p)

    def sign(self, message):
        z = bytes_to_long(sha256(message).digest())
        d = bytes_to_long(flag[8:-1])
        k = random.getrandbits(256) + bytes_to_long(os.urandom(16))
        r = bytes_to_long(os.urandom(32))
        s = pow(k, -1, self.p) * (z + d * r)
        return s % self.p, r

print('I am obsessed with RNGs, aint I?')
p = int(input('Enter your prime: '))
assert isPrime(p) and (100 < p.bit_length() < 256)
rng = RNG(p, random.randint(1, p), random.randint(1, p))

while True:
    print('Press 1 to get a sample!')
    print('Or, press 2 to sign your message!')
    opt = int(input('> '))
    if opt == 1:
        sample = rng.sample()
        print('Here you go => ', sample)
    elif opt == 2:
        message = input('> ').encode()
        sign = rng.sign(message)
        print('Your sign is ready => ', sign)
    else:
        break
```

The flow of this program is briefly,

1. We provide the server with a prime $p$ of our choice, which should conform to a range of bit lengths.
2. The server initializes the `rng` with our prime, an unknown generator $g$, and an unknown seed `seed`.
3. We can then either ask for a sample, in which case it gives us $g ^ x \mod p$ where $x$ is a $245$-bit random number generated using the standard python random library.
4. Or, we can sign a message $m$ of our choice, which then gives us `DSA` sign pairs, $s = k^{-1}(\text{sha256}(m) + d\cdot r) \mod p, r$. Here, the `DSA` nonce $k$ is generated as a sum of outputs from the random library and the secure `os` library.


## Solving the challenge

There's nothing novel or new, apparently, in this challenge. It uses pretty standard tricks, as far as crypto CTFs are concerned. Roughly, the solution path can be divided into the following steps:

1. Generate a prime with a smooth order and give it to the server.
2. Discrete log with a known generator, normalize the base to do HNP, and retrieve the outputs of `random.getrandbits(245)`.
3. As the standard python library is not secure, we can predict future outputs of it, when given with enough outputs of the library.
4. The last step is to do another HNP on the `DSA` signatures and retrieve the flag.

That said, let's dive deeper into these steps individually.

### Generating smooth primes

This is the easier step compared to the rest. What we simply do is keep brute-forcing with small primes and check if their product (added to 1) generates a prime or not i.e $p - 1 = \prod_{i=1}a_i^{e_i}$, where $a_i \approx 2^{16}$.  

```python
while True:
    used = []
    p = 2
    for _ in range(16):
        p_ = getPrime(16)
        used.append(p_)
        p *= p_
        
    p += 1
    if is_prime(p) and int(p).bit_length() == 253:
        print(p)
        print(used)
        break
        
#12897945447809707674858877261739662089690448124013208287050632691101014082259
#[48781, 52051, 62761, 61331, 47903, 62303, 61673, 48859, 54013, 61487, 60647, 47951, 51199, 38273, 61211, 63337]
```
The rationale behind doing this is that, as we shall see on the next step, doing discrete log becomes trivial.

### Discrete logarithms and HNP to get the randoms

The first query gives us $y_i = g^{x_i} \mod p$, where both $g, x_i$ are unknowns. If $g$ were known, we could have easily discrete log'ed here and gotten the $x_i$'s. However, since that's not the case, we have to opt for a different plan.
We work with a different known base $b$, instead of $g$. Let $g = b^k \mod p$. This means $y_i \equiv g^{x_i} \equiv (b^k)^{x_i} \equiv b^{k\cdot x_i} \mod p$. Discrete logarithms are now doable, and doing so gives us a bunch of equations like $z_i = k \cdot x_i \mod (p-1)$ where only the $z_i$'s are known. We can cancel out the $k$ via division, and have an equation only in terms of the known $z_i$'s and the unknown $x_i$'s. That is, 

$$
\begin{aligned}
\frac{z_0}{z_i} & \equiv \frac{k \cdot x_0}{k \cdot x_i} && \mod (p-1) \\\
& \equiv  \frac{x_0}{x_i} && \mod (p-1) \\\
\rightarrow z_o \cdot x_i - z_i \cdot x_0 &\equiv 0 && \mod (p-1)
\end{aligned}
$$

This has now turned into the well-known `Hidden Number Problem (HNP)`. There are plenty of resources online and in other writeups. In fact, I have written a brief piece on this myself, on a previous [writeup of mine](https://tsumiiiiiiii.github.io/ebg/#part-4-recovering-the-lcg-seed-truncated-lcg-in-disguise).

```python
def solve_exponent(rs, mod):
    sz = len(rs)
    us = [var(f'u{i}') for i in range(sz)]
    
    bounds = {}
    for i in range(sz):
        bounds[us[i]] = (2^235, 2^245)
    
    eqs = []
    
    u0 = us[0]
    r0 = rs[0]
    
    for ri, ui in zip(rs[1:], us[1:]):
        eqs.append((u0 * ri - ui * r0 == 0, mod))
        
    load('https://gist.githubusercontent.com/Connor-McCartney/952583ecac836f843f50b785c7cb283d/raw/5718ebd8c9b4f9a549746094877a97e7796752eb/solvelinmod.py')
    sol = solve_linear_mod(eqs, bounds)
    ret = [int(sol[ui]) for ui in us]
    return ret

exps = [int(Fp(sample).log(base)) for sample in get_samples(100)]
print('Will solve the expos')
values = solve_exponent(exps, p - 1)
```
### Cracking python random

As it turns out, the `random` library in python is very unsafe. Given enough outputs from it, we can predict all future calls. Specifically, if we have 624 consecutive outputs from `random.getrandbits(32)`, it's feasible to predict whatever the `random` module would output next. Problems of this flavor are infact very common and appear frequently, such as [here](https://fireshellsecurity.team/utctf2023-calculator/) and [here](https://ctftime.org/writeup/36330). There's also a python [library](https://github.com/tna0y/Python-random-module-cracker) that deals with this, i.e given 624 outputs of 32 bits, predict the next ones.

However, the situation in this problem is a bit different from the ones above in that it doesn't give $32$ bits of output. We instead have $245$ bits output. What internally happens is, the library makes $256// 32 = 8$ calls to `getrandbits(32)` (not exactly, but the process is very similar). On the last call, however, the $11$ lsbs are stripped off to produce a $21$ bit number, thus making a $32*7 + 21=245$ bit number. This means we lose $11$ bits of information per call. 

There are existing implementations available to handle such cases, such as [ice monster's](https://github.com/icemonster), [deuterimu's](https://github.com/deut-erium/RNGeesus), [maple3142's](https://github.com/maple3142/gf2bv), and [rbtree's](https://rbtree.blog/posts/2021-05-18-breaking-python-random-module/). While maple's and rbtree's implementations can handle complicated cases, the ice-monster's repo is simple and good enough to do the job here. 
```python
def solve_random(states):
    ut = Untwister()
    for random_num in states:
        #Just send stuff like "?11????0011?0110??01110????01???"
        rnums = []
        rem = (1<<32) - 1
        for i in range(8):
            rnums.append(bin(random_num & rem)[2:])
            random_num >>= 32
        rnums[-1] += '?'*11
        for num in rnums:
            ut.submit(num)

    print('will do rand cracking now')
    r2 = ut.get_random()
    return r2
```

{{< admonition type=tip title="Food for thought" open=true >}}
This is probably the step where AI kept failing. Mainly because AI kept suggesting `randcrack` libary, which is not suitable for this challenge. Also, it has a big ego problem
of trying to code everything from scratch, so there's that. 
{{< /admonition >}}

### Abusing the broken `DSA` signing with yet another HNP

Now that we can predict whatever `random.getrandbits(256)` calls will produce, solving the rest becomes trivial. We have,

$$
\begin{aligned}
s_i &= k_i^{-1}(z_i + d\cdot r_i) &&\mod p \\\
\rightarrow s_i \cdot k_i &= z_i + d\cdot r_i &&\mod p \\\
\rightarrow s_i \cdot (x_i + e_i) &= z_i + d\cdot r_i &&\mod p \\\
\rightarrow s_i \cdot x_i + s_i \cdot e_i &= z_i + d\cdot r_i &&\mod p
\end{aligned}
$$

In this equation, $d$ is the flag, $z_i = \text{sha256}(m_i)$ is known, $s_i, r_i$ is given, $x_i$ can be predicted because "python random". So this becomes another HNP instance with the unknown $d$ and the secure randoms $e_i$'s.

```python
def solve_DSA(rs, ss, zs, ks, mod):
    sz = len(rs)
    es = [var(f'e{i}') for i in range(sz)]
    d = var('d')

    bounds = {d : (2^128, 2^230)}
    for ei in es:
        bounds[ei] = (2^110, 2^128)

    eqs = []
    for ri, si, zi, ki, ei in zip(rs, ss, zs, ks, es):
        lhs = si * (ki + ei)
        rhs = zi + d * ri
        eqs.append((lhs==rhs, mod))

    sol = solve_linear_mod(eqs, bounds)
    print(sol)
    return sol[d]
```

The whole solution code is as follows:

```python
import time
from pwn import *
from Crypto.Util.number import long_to_bytes, getPrime, isPrime, bytes_to_long
from hashlib import sha256

def solve_exponent(rs, mod):
    sz = len(rs)
    us = [var(f'u{i}') for i in range(sz)]
    
    bounds = {}
    for i in range(sz):
        bounds[us[i]] = (2^235, 2^245)
    
    eqs = []
    
    u0 = us[0]
    r0 = rs[0]
    
    for ri, ui in zip(rs[1:], us[1:]):
        eqs.append((u0 * ri - ui * r0 == 0, mod))
    
    sol = solve_linear_mod(eqs, bounds)
    ret = [int(sol[ui]) for ui in us]
    return ret

def solve_random(states):
    ut = Untwister()
    for random_num in states:
        #Just send stuff like "?11????0011?0110??01110????01???"
        rnums = []
        rem = (1<<32) - 1
        for i in range(8):
            rnums.append(bin(random_num & rem)[2:])
            random_num >>= 32
        rnums[-1] += '?'*11
        for num in rnums:
            ut.submit(num)

    print('will do rand cracking now')
    r2 = ut.get_random()
    return r2

def solve_DSA(rs, ss, zs, ks, mod):
    sz = len(rs)
    es = [var(f'e{i}') for i in range(sz)]
    d = var('d')

    bounds = {d : (2^128, 2^230)}
    for ei in es:
        bounds[ei] = (2^110, 2^128)

    eqs = []
    for ri, si, zi, ki, ei in zip(rs, ss, zs, ks, es):
        lhs = si * (ki + ei)
        rhs = zi + d * ri
        eqs.append((lhs==rhs, mod))

    sol = solve_linear_mod(eqs, bounds)
    print(sol)
    return sol[d]
    
        
def get_samples(cnt):
    samples = []
    for _ in range(cnt):
        io.recvuntil(b'> ')
        io.sendline(b'1')
        samples.append(int(io.recvline().decode().strip().split('> ')[-1]))
    return samples

def get_signs(cnt):
    rs, ss, zs, ks = [], [], [], []
    for i in range(cnt):
        io.recvuntil(b'> ')
        io.sendline(b'2')
        io.recvuntil(b'> ')
        msg = str(i)
        io.sendline(msg.encode())
        z = bytes_to_long(sha256(msg.encode()).digest())
        s, r = eval(io.recvline().decode().strip().split('> ')[-1])
        rs.append(r)
        ss.append(s)
        zs.append(z)
    return rs, ss, zs


t1 = time.time()

#This was used to generate the smooth prime
# while True:
#     used = []
#     p = 2
#     for _ in range(16):
#         p_ = getPrime(16)
#         used.append(p_)
#         p *= p_
        
#     p += 1
#     if is_prime(p) and int(p).bit_length() == 253:
#         print(p)
#         print(used)
#         break

p = 12897945447809707674858877261739662089690448124013208287050632691101014082259

Fp = Zmod(p)
base = Fp.multiplicative_generator()

io = remote('127.0.0.1', 6469)

io.recvline()
io.recvuntil(b': ')
io.sendline(str(p).encode())

exps = [int(Fp(sample).log(base)) for sample in get_samples(100)]
print('Will solve the expos')
values = solve_exponent(exps, p - 1)

exps2 = [int(Fp(sample).log(base)) for sample in get_samples(100)]
print('Will solve the expos')
values2 = solve_exponent(exps2, p - 1)

rand = solve_random(values + values2)

ks = [rand.getrandbits(256) for _ in range(10)]
rs, ss, zs = get_signs(10)

print('Will solve the DSA now')

sol = solve_DSA(rs, ss, zs, ks, p)
print(long_to_bytes(sol))

t2 = time.time()

print(t2 - t1)
```

## Key takeaways

1. python random is extremely unsafe. Even a single bit leakage can cause the whole rng to break.
2. HNP is a very standard problem that appears frequently in cryptography CTFs. 

