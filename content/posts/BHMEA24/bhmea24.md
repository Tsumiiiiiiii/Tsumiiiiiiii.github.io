---
weight: 1
title: "BlackHat MEA 2024 Quals - Trypanophobia and Cheeky  writeup"
date: 2024-09-02T22:30:00+06:00
lastmod: 2024-09-02T22:30:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for  Trypanophobia and Cheeky from BlackHat MEA 24 Quals."

tags: ["crypto", "BlackHatMEA", "RSA", "math", "nth-roots", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true

toc:
  enable: true
  position : "left"
---

Writeup for  Trypanophobia and Cheeky from BlackHat MEA 24 Quals.


<!--more-->


## Trypanophobia

This was an interactive challenge where the server code is as follows:

<div class="pre-wrapper">
<pre>
#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Qualifiers
#
# [Easy] Crypto - Trypanophobia
#

# Native imports
import os, json, hashlib

# Non-native imports
from Crypto.Util.number import getPrime, isPrime, inverse, GCD     # pip install pycryptodome

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{506f6c796d65726f5761734865726521}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Functions & Classes
class RSAKey:
    def __init__(self):
        self.public = None
        self.private = None
        
    @staticmethod
    def new():
        p = getPrime(1024)
        while True:
            q = getPrime(1024)
            f = (p - 1) * (q - 1)
            if GCD(f, 0x10001) == 1:
                break
        key = RSAKey()
        key.public = {
            'e' : 0x10001
        }
        key.private = {
            'p' : [p, q]
        }
        key.update()
        return key
    
    def update(self):
        self.public['n'] = 1
        self.private['f'] = 1
        for p in self.private['p']:
            self.public['n'] *= p
            self.private['f'] *= (p - 1)
        self.private['d'] = inverse(self.public['e'], self.private['f'])

    def pad(self, x):
        y = int(hashlib.sha256(str(set(self.private['p'])).encode()).hexdigest(), 16)
        while x < self.public['n']:
            x *= y
        x //= y
        return x
        
    def encrypt(self, x):
        if 0 < x < self.public['n']:
            return pow(self.pad(x), self.public['e'], self.public['n'])
        else:
            return 0


# Challenge set-up
HDR = """|
|  ┏┳┓              ┓   ┓ •
|   ┃ ┏┓┓┏┏┓┏┓┏┓┏┓┏┓┣┓┏┓┣┓┓┏┓
|   ┻ ┛ ┗┫┣┛┗┻┛┗┗┛┣┛┛┗┗┛┗┛┗┗┻
|        ┛┛       ┛"""
print(HDR)

ourKey = RSAKey.new()


# Server loop
TUI = "|\n|  Menu:\n|    [A]dd a key\n|    [E]ncrypt flag\n|    [Q]uit\n|"

while True:
    try:

        print(TUI)
        choice = input("|  > ").lower()

        if choice == 'q':
            print('|\n|  [~] Goodbye ~ !\n|')
            break
        
        elif choice == 'a':
            uin = json.loads(input("|  > (JSON) "))
            assert uin.keys() == {'p', 'q'}
            if all([
                isPrime(uin['p']), isPrime(uin['q']),
                len(bin(uin['p'])) == 1024 + 2,
                len(bin(uin['q'])) == 1024 + 2
            ]):
                ourKey.private['p'] += [uin['p'], uin['q']]
                ourKey.update()
            else:
                print('|  [!] Invalid primes.')

        elif choice == 'e':
            enc = ourKey.encrypt(int.from_bytes(FLAG, 'big'))
            print('|  Flag = 0x{:x}'.format(enc))

        else:
            print('|  [!] Invalid choice.')

    except KeyboardInterrupt:
        print('\n|\n|  [~] Goodbye ~ !\n|')
        break

    except Exception as e:
        print('|  [!] ERROR :: {}'.format(e))
```

What happens here is:

1. The server generates two primes both $1024$ bits. Then it *updates* the state where the public key ($n$) and ϕ ($f$) is calculated. $n = \prod_{i=1}^{n} p_i$ and $f = \prod_{i=1}^{n}(p_i - 1)$. **Nor the public key, neither the ϕ is ever revealed to the players**. 
2. We can interact with the server in $2$ ways ($3$ actually but who cares about *quit*). 
3. The first one is to add two keys to the already existing public keys with the condition being both of them should be $1024$ bits each. The `RSA` parameters are recalculated using the process mentioned in the previous step via the *update* function and the 2 new keys are added to the pool of primes.
4. The second type of query is to *encrypt* the `FLAG` with the current public key. It takes help of another function called *pad*. 

### Taking a closer look at the $pad$ function

The original message to be encrypted ($x$) is repeatedly multiplied by some hash value called $y$ until it becomes greater than the current public key ($n$). This can be mathematically represented as follows: $\text{pad(x)} = xy^k$ such that $\text{pad(x)} < n$ and $k$ is unknown (but can be somewhat guessed as we will see soon). 

But how is $y$ calculated? It is simply the $\text{SHA256}$ hash of the pool of primes (which is a list). There is a catch though, it doesn't take the list, rather, the **set of the list**, which is going to be the pivotal point of our exploitation. 

It's easy to see that $y$ is going to be of $256$ bits always as $\text{SHA256}$ hashes are of $32$ bytes.  

### Solution

We will take advantage of the **set** as mentioned before. Notice what happens if we add signatures multiple times with a constant prime $p$. Consider that the initial unknown public key was $n$ and the initial prime pool was $[P, Q]$. If we try to encrypt the `FLAG` now, we will get an unknown pad with an unknown $\text{pad(x)} = x\*y_{0}^k$. The $k$ value is within a specific range depending on the `FLAG` length, but it is generally within $5 \approx 20$. 

#### Add key with $uin[p] = uin[q] = p$ and *encrypt* `FLAG`

Notice that the prime pool is now $[P, Q, p, p]$ and it's set is $(P, Q, p)$. That means, $y_1 = \text{SHA256}((P, Q, p))$.  Also, $\text{pad(x)} = x\*y\_{1}^{k+8}$. The encrypted flag will be $E_1 = (x\*y\_{1}^{k+8})^e \mod (np^2)$ since public key is $n\*p^2$. 

Now why the exponent of $y_1$ is $8$ more than the last is intuitive. See that when we add two primes of $1024$ bits to the pool, the length of the public key increase by $2048$ bits. How many times *more* can we multiply $y_1$ (which is of $256$ bits) because of this increment? $\frac{2048}{256} = 8$ times and hence we can see the $8$ in the exponent. 

#### Add key again with $uin[p] = uin[q] = p$ and *encrypt* `FLAG`

The prime pool becomes $[P, Q, p, p, p, p]$. But the set? It's the same as before $(P, Q, p)$. And since $y$ depends solely on this particular set, we can say that $y_2 = y_1 =\text{SHA256}((P, Q, p))$. We have managed to fix the $y$. Now  $\text{pad(x)} = x\*y_{1}^{k+16}$. The encrypted flag will be $E_2 = (x\*y_{1}^{k+16})^e \mod (np^4)$ since public key is $n*p^4$. 

#### Lining up the equations

We have $E_1 = (x\*y_{1}^{k+8})^e \mod (np^2)$ and $E_2 = (x\*y_{1}^{k+16})^e \mod (np^4)$. We need to remove the $e$ from the exponent somehow. That's basic RSA decryption. But wait, we don't even know the whole public key ($n$ is unknown).  That's not a problem since we know the partial public key($p^2$ and $p^4$ since $p$ was provided by us to begin with). We can reduce the problem to

$$
\begin{aligned}
&E_{1}' &\equiv E_{1} &\equiv (x\*y_{1}^{k+8})^e &\mod p \\\ 
&E_{2}' &\equiv E_{2} &\equiv (x\*y_{1}^{k+16})^e &\mod p 
\end{aligned}
$$

We can now decrypt both $E_{1}'$ and $E_{2}'$ using $ϕ=p-1$ to get

$$
\begin{aligned}
&M_{1} &\equiv x\*y_{1}^{k+8} &\mod p \\\ 
&M_{2} &\equiv x\*y_{1}^{k+16} &\mod p 
\end{aligned}
$$

This lets us do $M_{2} / M_{1}$ to get $c = y_{1}^{8} \mod p$, where $c$ is known. We have to find $y_1$. Doing so is easy as there are built in methods in `sage`. 

```python
F = GF(p)
R.<x> = PolynomialRing(F)
polynomial = x^8 - c
y = polynomial.roots()[1][0] #Takes around 7 minutes on my potato

assert y^8 == c
</pre>
</div>

Once we get $y_1$, we can get $x = \frac{M_1}{y_{1}^{k+8}} \mod p$. But we don't know $k$. Remember that I mentioned $k$ can be brute-forced as it's in the range of $5 \approx 20$. So we try all values of $k$ and see which yields the correct `FLAG`.

```python
for k in range(5, 20):
	x = M1 * pow(y, -(k+8), p) % p
	print(long_to_bytes(x))
```

---




