---
weight: 1
title: "BUET CTF 2024 Finals - Writeups for my authored crypto challenges"
date: 2024-10-31T22:30:00+06:00
lastmod: 2024-10-31T22:30:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeups for Military Grader Counter, baby RSA revenge from BUET CTF 24 finals."

tags: ["crypto", "BUETCTF", "math", "RSA", "AES-CTR", "CRT", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true

---

Writeups for Military Grader Counter, baby RSA revenge from BUET CTF 24 finals
<!--more-->

BUET CTF 2024 ended on a high note. From the infrastructure to the management - everything deserves a solid 10, no less. Although not unexpected, quite a lot of problems from the finals went unsolved, with a substantial jump in difficulty from the qualifiers. Very often we see that teams topping nationals CTFs fumble during quality international CTFs, especially when they encounter a "hard" problem, as the national CTFs mostly host "easy" problems. The difficult problems in this round, hence, was a small attempt to "bridge" that difficulty gap. We hope the contestants would be more motivated to approach relatively harder poblems the next time they attempt a quality CTF.

That said, I wrote $2$ problems for this round, both of them being crypto. `Military Grade Counter` was on the easier side, having $4$ solves only (I exptected more than $10$ solves though), while the baby RSA revenge problem went unsolved, which was on the more difficult side of things.  

## baby RSA revenge

This script for this problem is as follows:

```python
#!/usr/local/bin/python
from Crypto.Util.number import getPrime, bytes_to_long as b2l, long_to_bytes as l2b
import random

print("Welcome to delphi's query service (Again)!!")

primes = [getPrime(512) for _ in range(6)]

with open('flag.txt', 'rb') as f:
    flag = f.read()
    
m = b2l(flag)
assert(m.bit_length() > 1200 and m.bit_length() < 1500)

used_indices = set()
for _ in range(6):
    op = int(input('Enter the type of operation you want to do: '))

    if op == 1:
        i, j = map(int, input('Enter 2 indices for primes to be used for RSA (eg. 0 4): ').split())
        if i in used_indices or j in used_indices or i < 0 or j < 0 or i == j:
            print('Illegal values given!!')
            exit(2)
            
        i, j = i % 6, j % 6

        if i == j:
            print("Don't try to be too clever mister!")
            exit(2)
        
        used_indices.add(i)
        used_indices.add(j)
        
        p, q = primes[i], primes[j]
        n = p * q
        e = 0x10001

        msg = int(input('Enter what you want to encrypt: '))
        assert 0 < msg < n, "????"

        ct = pow(msg, e, n)
        print('ct = ', ct)

    elif op == 2:
        i, j = 0, 0
        while i == j:
            i, j = random.randint(0, 5), random.randint(0, 5)
        
        p, q = primes[i], primes[j]
        n = p * q
        e = 0x10001

        ct = pow(m, e, n)
        print('ct = ', ct)

    else:
        print('~~Invalid operation~~')
        exit(2)
```

Initially $6$ primes are generated ($p_0, p_1, \cdots, p_5$) where $p_i < 2^{512}$ ($512$ bits). And then we are allowed to do $6$ queries on them. Queries available are of two types:

- [`1`] Send two integers $i, j$ which basically denotes the prime indices to be used for RSA encryption. Then send in another message $m$. We are returned $m^e \mod n$ where $n=p_i \cdot p_j$. Need to ensure $0 < m < n$ and $i, j \ge 0, i \ne j$. Another thing to notice is that we can't reuse prime indices. That is, if we have used $i = 1$ once, we can't use it again. 
- [`2`] Randomly selects two indices $i, j$ where $i \ne j$ and returns $\text{flag}^e \mod n$ where $n = p_i \cdot p_j$.

Note that in neither of the queries are we given $n$, the public modulus. So this becomes an extra burden which was not in the previous version.

### Leaking one prime

If you see the [original problem](https://tsumiiiiiiii.github.io/fh23_crypto/#baby-rsa) (also linked in the challenge description), you will find that I have talked about the classic GCD attack which could help solve the original problem. Well, you can't use that in the same way here (since $n$ is unknown), but something similar can be applied. 

Suppose we want to leak the second prime $p_1$. This can be done with two queries of type `1`:

- Send $(i, j) = (0, 1)$ and $m=2$. We get $ct_1 = 2^e \mod p_0 \cdot p_1$. 
- Send $(i, j) = (7, 2)$ and $m=2$. We get $ct_2 = 2^e \mod p_1 \cdot p_2$. This happens because $7 \mod 6 = 1$.  

$$
\begin{aligned}
ct_1 &\equiv 2^e &&\mod p_0 \cdot p_1 \\\
2^e - ct_1 &\equiv 0 &&\mod p_0 \cdot p_1 \\\
2^e - ct_1 &= k_1 \cdot p_0 \cdot p_1 
\end{aligned}
$$

The LHS in this equation is known to us. And the $k_1$ in the RHS is some unknown variable that we don't care about right now. 

In the same way, we can write $2^e - ct_2 = k_2 \cdot p_1 \cdot p_2$ for the second equation as well. If we take the GCD of these two LHS terms, we get $\text{GCD}(2^e - ct_1, 2^e - ct_2) = \text{GCD}(k_1 \cdot p_0 \cdot p_1, k_2 \cdot p_1 \cdot p_2) = k \cdot p_1$. With extremely high probability, $k$ is going to be some random low value which we can "clean up" by dividing with numbers in a small range (say upto $10000$). And then what we are left with is $p_1$ itself. 

{{< admonition type=tip title="Update on remaining queries" open=true >}}
We have spent $2$ queries on this step, meaning only $4$ queries remain.
{{< /admonition >}}

### Leaking some more primes

To be exact, we aim to leak $2$ more primes (giving us $3$ primes in total, which is sufficient for the problem). By spending two more queries of type `1`:

- Send $(i, j) = (8, 3)$ and $m=2$. We get $ct_3 = 2^e \mod p_2 \cdot p_3$.
- Send $(i, j) = (9, 4)$ and $m=2$. We get $ct_4 = 2^e \mod p_3 \cdot p_4$. 

Using the method shown in the previous step, we can :

- Leak $p_2$ using $ct_2, ct_3$.
- Leak $p_3$ using $ct_3, ct_4$. 

{{< admonition type=tip title="Update on remaining queries" open=true >}}
We have spent $2$ more queries on this step, meaning only $2$ queries remain.
{{< /admonition >}}

### Getting the flag 

Note that the previous two steps were deterministic. But this one is probabilistic. That is, we might have to open multiple instances in order to get this particular step right. 

Notice that `assert(m.bit_length() > 1200 and m.bit_length() < 1500)` ensures we need atleast two encryptions of the flag (but $3$ primes since $3$ primes can give us more than $1500$ bits). 

We make two queries of type $2$:

- Get the encrypted flag $ct_1 = \text{flag}^e \mod n_1$.
- Get the encrypted flag $ct_2 = \text{flag}^e \mod n_2$.

In both the queries, the $n$ is unknown and we have no control over them, unlike type `1` queries (where we could control them as willed). 

{{< admonition type=tip title="Update on remaining queries" open=true >}}
The last $2$ queries are spent on this step, meaning no more queries remain.
{{< /admonition >}}

This is where the issue of probability comes in. We assume (<strike>pray and hope</strike>) that the $3$ primes we have recovered so far ($p_1, p_2, p_3$) will be the factors of $n_1, n_2$ (there might be another unknown factor but that is not important for now).

In the instance that $p_1, p_2, p_3$ are indeed factors of $n_1, n_2$, there can be many possible cases, like $n_1 = p_1 \cdot p_2, \ n_2 = p_3 \cdot p_x$, or $n_1 = p_1 \cdot p_3, \ n_2 = p_2 * p_x$, or $n_1 = p_1 \cdot p_x, \ n_2 = p_2 \cdot p_3$. There might be some other cases as well (which can be easily taken care of by some trivial brute force). 

But how do we know that we have indeed hit a lucky instance? We try to decrypt the flag with our assumptions, and see if that yields a valid flag (check if the correct prefix is there). Since we have two ciphertexts, we "assume" $n_1 = p_1 \cdot p_2$.  Which means we can get two decryptions of the form $\text{flag} \mod p_1, \ \text{flag} \mod p_2$. And using $ct_2$, we can have another decryption $\text{flag} \mod p_3$. Then combine them using the `CRT`, to give us $\text{flag} \mod p_1 \cdot p_2 \cdot p_3$. Since the product of the primes would surpass $1500$ bits (each of them are $512$ bits each), we are "supposed" to get the correct flag, in the case that we have hit a lucky instance. 

If not, we rerun the entire thing again, and hopefully after like $20-25$ runs, we can get the flag with high probability. 

```python
from Crypto.Util.number import long_to_bytes as l2b, isPrime, GCD
from pwn import *
from functools import reduce

context.log_level = 'error'

def get_conn():
    io = remote('127.0.0.1', 5420)
    return io

def query1(io, i, j, m):
    io.recvuntil(b': ')
    io.sendline(b'1')

    io.recvuntil(b': ')
    io.sendline(str(i).encode() + b' ' + str(j).encode())
    io.recvuntil(b': ')
    io.sendline(str(m).encode())
    return int(io.recvline().decode().strip().split('= ')[-1])

def query2(io):
    io.recvuntil(b': ')
    io.sendline(b'2')
    return int(io.recvline().decode().strip().split('= ')[-1])

def clean(x):
    for d in range(2, 10000):
        while x % d == 0:
            x = x // d
    return x

def get_prime(ct1, ct2):
    e = 0x10001
    l1 = (2**e) - ct1
    l2 = (2**e) - ct2

    l1, l2 = clean(l1), clean(l2)
    
    p = GCD(l1, l2)
    p = clean(p)
    assert isPrime(p)
    return p

def decrypt(ct, p, q):
    e = 0x10001
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return pow(ct, d, p * q)

def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * pow(p, -1, n_i) * p
    return sum % prod

def get_flag(ct1, ct2, primes):
    e = 0x10001
    for i in range(3):
        for j in range(3):
            msg1 = decrypt(ct1, primes[i], primes[j])
            if i == j: continue
            for k in range(3):
                for l in range(3):
                    if k == l: continue
                    if i == k or j == k: continue
                    msg2 = decrypt(ct2, primes[k], primes[l])
                    msg = l2b(chinese_remainder([primes[i], primes[j], primes[k]], [msg1 % primes[i], msg1  % primes[j], msg2 % primes[k]]))
                    if b'BUETCTF' in msg:
                        return msg
    return -1

def solve(io):
    io.recvline()

    ct1 = query1(io, 0, 1, 2)
    ct2 = query1(io, 7, 2, 2)
    ct3 = query1(io, 8, 3, 2)
    ct4 = query1(io, 9, 4, 2)
    p, q, r = get_prime(ct1, ct2), get_prime(ct2, ct3), get_prime(ct3, ct4)

    ct1 = query2(io)
    ct2 = query2(io)

    flag = get_flag(ct1, ct2, [p, q, r])
    if flag == -1:
        return False
    else:
        print(flag.decode())
        return True

while True:
    print('Trying...')
    if solve(get_conn()):
        break
```

---

## Military Grade Counter

This is the given challenge file:

```python
#!/usr/local/bin/python

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class COUNTER():
    def __init__(self, key, iv):
        self.key, self.iv = key, iv
        self.block_size = 16
        self.counter = 0

    def __get_blocks(self, pt):
        blocks = []
        for i in range(0, len(pt), self.block_size):
            blocks.append(pt[i : i + self.block_size])
        return blocks
    
    def __xor(self, sa, sb):
        return bytes([a^b for a, b in zip(sa, sb)])
    
    def __encrypt(self, block):
        stream = AES.new(key, AES.MODE_ECB).encrypt(
                    iv + int(self.counter & 0xFF).to_bytes(2, 'big'))
        self.counter += 1
        return self.__xor(block, stream)

    def encrypt(self, pt):
        blocks = self.__get_blocks(pad(pt, self.block_size))
        ct = []
        for block in blocks:
            ct.append(self.__encrypt(block).hex())
        return ''.join(block for block in ct)
    

print('Welcome to my next gen military grade symmetric encryption!!')

key, iv = os.urandom(16), os.urandom(14)
cipher = COUNTER(key, iv)

enc = cipher.encrypt(open('flag.txt', "rb").read())
print(f'Have an encrypted flag: {enc}')

pt = bytes.fromhex(input('Let me encrypt for you this one time: '))
ct = cipher.encrypt(pt)
print(f'Here you go: {ct}')
```

So basically we are given some sort of encryption scheme that uses `AES-ECB` in it (which is supposed to behave like counter mode of operation). We are given the encrypted flag, as well as the encryption of a message according to our choice.

### Understanding the encryption procedure

All though you don't really need to understand how counter mode of operation works in AES, a little knowledge definitely helps. I have already written a [writeup](https://tsumiiiiiiii.github.io/bhmea24/#a-primer-on-aes-ctr) where a small intro to this have been given. You can check that out, or you can check wikipedia. Either way, the underlying encryption is very similar to that of CTR mode. 

We see that whatever input is given, it is divided into blocks of $16$. Each block is "separately" encrypted. To start, the `COUNTER` scheme takes in as input two things - a key ($16$ bytes) and an iv ($14$ bytes). Another variable can be seen there, if we take a closer look - the so called `counter` variable. The encryption function can be represented as the following operations:

1. Convert the counter variable to bytes (of length $2$). But before that, the integer form of counter is "AND"ed with $\text{0xFF}$. That is, $iv' = iv \ || \ \text{to-bytes}(\text{counter} \ \\& \ \text{0xFF})$, where $||$ denotes string concatenation.
2. Next is where the actual AES thing happens, a stream is generated as $\text{AES-ECB}(iv')$. The encryption key is ofcourse constant and provided to the class before any encryptions are done. 
3. The generated stream is "XOR"ed with the provided block. 
4. Next the counter is increase by $1$. 

To put it simply, the encryption function can be represented as:

$$
\begin{aligned}
\mathcal{E}(\text{block}) = \text{AES-ECB}(iv \ || \ \text{to-bytes}(\text{counter})) \oplus \text{block}
\end{aligned}
$$

As is the main property of a counter mode of operation - the text to be encrypted is not "encrypted" via AES, rather it is "XOR"ed with a stream (which is generated using AES). 

### Exploiting this encryption method

As you have guessed, we are done if we can recover the $\text{AES-ECB}(iv \ || \ \text{to-bytes}(\text{counter}))$ portion somehow, because then just a simple xor is enough to reveal the plaintext. The main point of exploitation lies here : `iv + int(self.counter & 0xFF).to_bytes(2, 'big'))`. To be more specific, the "AND"ing with `0xFF`. 

For a moment, lets forget about all the AES gimmic there is, and concentrate solely on what "AND"ing with `0xFF` implies. `0xFF` in hex is simply $1111111$ in binary. Which means, "AND"ing any number with this particular number will ommit any bit higher than $8$, and keep the lower $8$ bits "intact". It works as a mask per se. 

$$
\begin{align*}
11010101 \ \& \ 11111111 &= \underbrace{11010101}\_{\text{the whole number remains unchanged}} \\\
1101\textcolor{blue}{10101101} \ \& \ 11111111 &= \underbrace{0000}\_{\substack{\text{4 high} \\ \text{bits omitted}}} \ \underbrace{\textcolor{blue}{10101101}}\_{\substack{\text{lower 8 bits} \\ \text{remain unchanged}}}
\end{align*}
$$

And this is what we will exploit. Notice that, once we cross $255$, and step to $256$, we enter the realm of $9$ bit numbers. And what will "AND"ing with `0xFF` do? Exactly, ommit the higher bits. $256$ in binary is $100000000$, and so $100000000 \ \\& \ 11111111 = 00000000$ as the $9$th bit ($1$) is ommitted. So when used as the counter, $256$ behaves exactly like how $0$ would behave.

That is, if we refer $iv_i = iv \ || \ \text{to-bytes}(i \ \\& \ \text{0xFF})$, then $iv_0 = iv_{256}$ holds, because $0 \ \\& \ \text{0xFF} = 256 \ \\& \ \text{0xFF}$. This lets us write $iv_1 = iv_{257}, \ iv_2 = iv_{258}, \ iv_3 = iv_{259}$ and so on.

### Retrieving the flag

Since we can send a message of any length to be encrypted, we can send in around $300$ blocks of $0s$ (each block has $16$ $0s$ each). This will give us the streams generated using $\text{AES-ECB}$ encryption, i.e. $\text{AES-ECB}(iv_{i})$ can be obtained. Since we know that the first block of flag was "XOR"ed with  $\text{AES-ECB}(iv_{0})$, we can "XOR" it back with  $\text{AES-ECB}(iv_{256})$ to get the first block of flag. 

$$
\begin{aligned}
&\mathcal{E}(\text{block}\_0) \oplus \text{AES-ECB}(iv_{256}) \\\
&= (\text{block}\_0 \oplus \text{AES-ECB}(iv_{0})) \oplus \text{AES-ECB}(iv_{256}) \\\
&= (\text{block}\_0 \oplus \text{AES-ECB}(iv_{0})) \oplus \text{AES-ECB}(iv_{0}) \\\
&= \text{block}_0
\end{aligned}
$$

And in this way the later blocks can be recovered too - $\mathcal{E}(\text{block}\_i) \oplus \text{AES-ECB}(iv_{256 + i}) = \text{block}_i$

```python
from pwn import *

context.log_level = 'error'

def get_conn():
    io = remote('127.0.0.1', 5069)
    return io

def __xor(sa, sb):
    return bytes([a^b for a, b in zip(sa, sb)])

def __get_blocks(pt):
    blocks = []
    for i in range(0, len(pt), 16):
        blocks.append(pt[i : i + 16])
    return blocks

io = get_conn()
io.recvuntil(b': ')
ct = __get_blocks(bytes.fromhex(io.recvline().decode().strip()))
sz = len(ct)

io.recvuntil(b': ')
to_send = b'\x00'*16*275
io.sendline(to_send.hex().encode())
stream_blocks = __get_blocks(bytes.fromhex(io.recvline().decode().strip().split(': ')[-1]))

j = 0
flag = ''
for i in range(256 - sz, 256):
    m = __xor(ct[j], stream_blocks[i])
    flag += m.decode()
    j += 1

print(flag)
```
