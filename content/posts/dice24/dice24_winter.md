---
weight: 1
title: "DiceCTF 2024 - Winter"
date: 2024-02-15T16:37:00+06:00
lastmod: 2024-02-15T16:37:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for the winter Cryptography challenge."

tags: ["crypto", "DiceCTF", "hash", "winternitz", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true

toc:
  enable: true
---

Writeup for the winter Cryptography challenge.

<!--more-->

This was quite fun as the introductory challenge. To begin with, we are provided with the following script:

```python
#!/usr/local/bin/python
import os
from hashlib import sha256

class Wots:
    def __init__(self, sk, vk):
        self.sk = sk
        self.vk = vk
        
    @classmethod
    def keygen(cls):
        sk = [os.urandom(32) for _ in range(32)]
        vk = [cls.hash(x, 256) for x in sk]
        return cls(sk, vk)
        
    @classmethod
    def hash(cls, x, n):
        for _ in range(n):
            x = sha256(x).digest()
        return x

    def sign(self, msg):
        m = self.hash(msg, 1)
        sig = b''.join([self.hash(x, 256 - n) for x, n in zip(self.sk, m)])
        return sig

    def verify(self, msg, sig):
        chunks = [sig[i:i+32] for i in range(0, len(sig), 32)]
        m = self.hash(msg, 1)
        vk = [self.hash(x, n) for x, n in zip(chunks, m)]
        return self.vk == vk

if __name__ == '__main__':
    with open('flag.txt') as f:
        flag = f.read().strip()

    wots = Wots.keygen()
    msg1 = bytes.fromhex(input('give me a message (hex): '))
    sig1 = wots.sign(msg1)
    assert wots.verify(msg1, sig1)
    print('here is the signature (hex):', sig1.hex())
    msg2 = bytes.fromhex(input('give me a new message (hex): '))
    if msg1 == msg2:
        print('cheater!')
        exit()
    sig2 = bytes.fromhex(input('give me the signature (hex): '))
    if wots.verify(msg2, sig2):
        print(flag)
    else:
        print('nope')
```

This is a somewhat(*faulty*) implementation of the `Winternitz Signature Scheme`. It works in a way very similar to one-time pads. 

## Winternitz Signature Scheme

Do note that this scheme has a lot of variants but here we are going to work with the simplest one.

### Key Generation

The set of public and private keys is generated as follows:

1. 32 random numbers are generated where each number is 256 bits. These are the private keys - `[private[0], private[1], ..., private[31]`]. 
2. To generate the set of public keys, each of the private keys generated from the last step is hashed 256 times - `[public[0], public[1], ..., public[31]]`. That is, $public_i = H^{256}(private_i)$. The hash function `H` is generally chosen to be `sha256`. 

![Key generation](https://github.com/Tsumiiiiiiii/Tsumiiiiiiii.github.io/blob/main/content/posts/dice24/kgw.svg?raw=true)

### Signature Generation

For any message, a signature has to be formed with the following steps:

1. The message `m` is hashed using `sha256`. As we know, `sha256` produces a digest of 256 bits. We divide those 256 bits into 32 chunks. Each chunk thus has a size of $256/32=8$ bits - `[N[0], N[1], ..., N[31]]`.
2.  Each of the private key`private[i]` is hashed a total of `256 - N[i]` times.  That is, $sign_i=H^{256-N_i}(private_i)$.

![Sign generation](https://github.com/Tsumiiiiiiii/Tsumiiiiiiii.github.io/blob/main/content/posts/dice24/sgw.svg?raw=true)
### Signature Verification

Lastly, it must be checked whether the signature obtained is valid or not. 

1.  For each `sign[i]` we hash it a total of `N[i]` times. Let's denote it by `V[i]`.
2.  For each `V[i]`, we check if `V[i] == public[i]`. If this holds, that particular signature is valid.
![Sign verify](https://github.com/Tsumiiiiiiii/Tsumiiiiiiii.github.io/blob/main/content/posts/dice24/svw.svg?raw=true)

Why does this work? 

$$
\begin{aligned} V_i &= H^{N_i}(sign_i) \\\\ &= H^{N_i}(H^{256-N_i}(private_i)) \\\\ &= H^{256}(private_i) \\\\ &= public_i \end{aligned}
$$

## The given problem

The program flow is as follows:
- We provide a message $m_1$.
- The server signs $m1$ and returns $sig_1$. 
- We must provide another message $m2$  and it's signature $sig_2$ so that $sig_2 = sig_1$. 
- If the above condition holds, we are given the flag.
- Neither the `private` nor the `public` is key is revealed.

Our job is to find another message $m_2$, whose signature $sig_2$ can be forged from known signature $sig_1$.

## Solving a slightly simpler problem

Instead of solving the problem as is, we are going to solve an easier version of it. Notice the line `m = self.hash(msg, 1)` in the `sign` function? For the time being, suppose that line is omitted and the `sign` function looks like this:

```python
def sign(self, msg):
    sig = b''.join([self.hash(x, 256 - n) for x, n in zip(self.sk, m)])
    return sig
```

As the first message $m_1$, we send `bbb...b` (32 b's). Since the ascii value of `b` is $98$, while calculating the sign each secret key will be hashed $256-98=158$ times. So the $sig_1$ array is going to contain $sig1_i=H^{158}(sk_i)$ where `sk[i]` is the private or secret key. 

For the second message $m_2$, if we send `aaa...a` (32 a's) we can easily predict what $sig_2$ is going to be. `b` has an ascii value of $97$ and so each secret key is hashed $256-97=159$ times. $sig2_i=H^{159}(sk_i)$. 

How do we calculate $sig_2$ from $sig_1$? Notice that

$$
\begin{aligned} sig2_i&=H^{159}(ski_i) \\\\ &= H(H^{158}(sk_i)) \\\\ &= H(sig1_i) \end{aligned}
$$

Hashing each $sig_1$ chunk once gives us chunks of $sig_2$. Thus $sig_2$ can easily be forged using the values of $sig_1$ and the problem is solved. In fact, for any character $c_1$ as $m_1$, if we send $c_2$ for $m_2$ (where $c_2>c_1$), the signature $sig_2$ can be formed. We simply hash $sig_1$ a total of $c_1-c_2$ times to get $sig_2$.  

## Tackling the original problem

The `sign` function is now going to look like this:

```python
def sign(self, msg):
        m = self.hash(msg, 1)
        sig = b''.join([self.hash(x, 256 - n) for x, n in zip(self.sk, m)])
        return sig
```

See that whatever message we input, is **hashed once first, then signed**.  We no longer have the liberty to send whatever $c$ to be signed like we had before. Becuase now $c_i=H(m)_i$.  

This *gimmick* makes the problem much more difficult than it was before. Because the 32 bytes produced from $sha{256}()$ is completely random. Suppose we send $msg_1=m_1m_2...m_{x}$. The sign we are getting back is $sig_1=h_1h_2...h_x$ where $h_i=H^{256-H(msg_1)_i}(private_i)$. 

If we want to calculate the $sig_2$ for $msg_2$ using $sig_1$ as we did for the easier variant, we have to hash the already known $h_1$ some known amount of times to get the relevant chunk for $sig_2$ that is $h'_i=H^{256-H(msg_2)_i}(private_i)$. Since we have to calculate $sig_2$ from $sig_1$, it must hold that there must be a $k_i$ for which, $h'_i=H^{k_i}(h_i)$. 

$$
\begin{aligned} h'_i&=H^{k_i}(h_i) \\\\ &= H^{k_i}(H^{256-H(msg_1)_i}(private_i)) \\\\ &= H^{256-H(msg_1)_i + k_i}(private_i) \end{aligned}
$$

Also, by the definition of the signature itself, it must hold that $h'_i=H^{256-H(msg_2)_i}(private_i)$. Thus the following has to be true,

$$
\begin{aligned} &256-H(msg_2)_i = 256-H(msg_1)_i+k_i \\\\ &=> H(msg_1)_i - H(msg_2)_i = k_i \\\\ &=> H(msg_1)_i > H(msg_2)_i \end{aligned}
$$

But coming up with such hashes by chance is extremely rare since by the property of any secure hash (which also includes $sha{256}$) the digest bytes must be completely random. 

That means our job is to find not just one hash but **two** hashes that satisfy

$$
\begin{equation} H(msg_1)_i > H(msg_2)_i \ \ \ \ \forall i = 0,1,.., 31 \end{equation}
$$

### Finding a good $msg_1$

The target is to find such a message whose hash digest bytes are as **large** as possible. That is we want to maximize $H(msg_1)_i$. Simply simulating for some time is enough to find such a hash.

```python
mx = -1
H = ''
msg = ''

for i in tqdm(range(10000000)):
  m = os.urandom(32)
  h = sha256(m).digest()
  x = min([i for i in h])
  if x > mx:
    mx = x
    H = h
    msg = m

print('\n')
print(mx)
print(msg)
for i in H: print(i, end = ' ')
```

```bash
100%|██████████| 10000000/10000000 [00:49<00:00, 201495.75it/s]

105
b'\xec\xd0\xa9\x1a\x93 B\x9fJ\xc9\xa9\x01\x92J\x07\x1b\xa3\x16\x1a\x11\xc6\x80N>\xe2@\x88Ck\x00\xdf\xb5'
217 129 252 162 196 205 253 116 110 127 242 141 144 247 127 170 105 226 142 105 154 183 247 197 183 219 179 157 214 184 218 120
```

### Finding a good $msg_2$

We must find a message whose hash digest bytes are as **low** as possible (lower than 105 for our code to be precise). 

```python
mxm = -1

for i in tqdm(range(1000000)):
  m = os.urandom(32)
  tgt = sha256(m).digest()
  
  cnt = sum(int(i <= j) for i, j in zip(tgt, H))

  mxm = max([mxm, cnt])
  if cnt == 32:
    print('\nYEEEEEEEEE')
    ans = m
    print(ans)
    break
```

```shell
 33%|███▎      | 330802/1000000 [00:03<00:06, 98534.94it/s]

YEEEEEEEEE
b'\xc7\x8b\xc0*6\x10\xb58\xdc\xe7\xea\x8aX[\x97\xa4\x8dDN\xbd\xd6\xf2\xaay\xa4\xe3{\xf1,$X\xfd'

32
```

Did not even take 5 seconds to find one!

### Calculating $sig_2$ from $sig_1$

As already explained in the easier variant, we can hash each chunk of $sig_1$ some particular amount of times ($k_i$) to get the corresponding chunk of $sig_2$.  $k_i = H(msg_1)_i - H(msg_2)_i$. And then $sig2_i=H^{k_i}(sig1_i)$. 

```python
sign2 = b''

for i, (h1, h2) in enumerate(zip(hash1, hash2)):
  sig = chunks[i]
  for i in range(h1 - h2):
    sig = sha256(sig).digest()
  sign2 += sig
```

Once the signature $sig_2$ is calculated, we can send it to the server and retrieve the flag.

> **dice{according_to_geeksforgeeks}**

