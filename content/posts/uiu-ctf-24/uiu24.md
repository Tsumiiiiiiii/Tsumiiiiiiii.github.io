---
weight: 1
title: "UIU CTF 2024 snore signature and key-in-haystack writeup"
date: 2024-07-07T00:37:00+06:00
lastmod: 2024-07-07T00:37:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for some Cryptography challenges from UIU CTF 24."

tags: ["crypto", "UIU CTF", "schnorr", "signature forgery", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true

toc:
  enable: true
---

Writeup for some Cryptography challenges from UIU CTF 24.


<!--more-->

Solved all crypto problems (finally 😍) in this edition of UIU CTF. The problems were trivially easy, to be honest. For a CTF of this calibre, the difficulty curve should be more steep. To put things into perspective, the most difficult crypto challenge (`key-in-haystack`) had more than 60 solves. I think the 22nd edition was perfect in terms of balanced difficulty. Nevertheless, the problems were still refreshing and fun to try. Here, I will make writeups for two challenges: `snore signature` and `key-in-haystack`.

## Snore Signature

This is the script that we are provided with:

```python
#!/usr/bin/env python3

from Crypto.Util.number import isPrime, getPrime, long_to_bytes, bytes_to_long
from Crypto.Random.random import getrandbits, randint
from Crypto.Hash import SHA512

LOOP_LIMIT = 2000

def hash(val, bits=1024):
    output = 0
    for i in range((bits//512) + 1):
        h = SHA512.new()
        h.update(long_to_bytes(val) + long_to_bytes(i))
        output = int(h.hexdigest(), 16) << (512 * i) ^ output
    return output

def gen_snore_group(N=512):
    q = getPrime(N)
    for _ in range(LOOP_LIMIT):
        X = getrandbits(2*N)
        p = X - X % (2 * q) + 1
        if isPrime(p):
            break
    else:
        raise Exception("Failed to generate group")

    r = (p - 1) // q

    for _ in range(LOOP_LIMIT):
        h = randint(2, p - 1)
        if pow(h, r, p) != 1:
            break
    else:
        raise Exception("Failed to generate group")

    g = pow(h, r, p)

    return (p, q, g)

def snore_gen(p, q, g, N=512):
    x = randint(1, q - 1)
    y = pow(g, -x, p)
    return (x, y)

def snore_sign(p, q, g, x, m):
    k = randint(1, q - 1)
    r = pow(g, k, p)
    e = hash((r + m) % p) % q
    s = (k + x * e) % q
    return (s, e)

def snore_verify(p, q, g, y, m, s, e):
    if not (0 < s < q):
        return False

    rv = (pow(g, s, p) * pow(y, e, p)) % p
    ev = hash((rv + m) % p) % q

    return ev == e

def main():
    p, q, g = gen_snore_group()
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"g = {g}")

    queries = []
    for _ in range(10):
        x, y = snore_gen(p, q, g)
        print(f"y = {y}")

        print('you get one query to the oracle')

        m = int(input("m = "))
        queries.append(m)
        s, e = snore_sign(p, q, g, x, m)
        print(f"s = {s}")
        print(f"e = {e}")

        print('can you forge a signature?')
        m = int(input("m = "))
        s = int(input("s = "))
        # you can't change e >:)
        if m in queries:
            print('nope')
            return
        if not snore_verify(p, q, g, y, m, s, e):
            print('invalid signature!')
            return
        queries.append(m)
        print('correct signature!')

    print('you win!')
    print(open('flag.txt').read())

if __name__ == "__main__":
    main()
```

From the challenge name it is understood that the problem is somehow related to `schnorr signatures`. Maybe there is some bug in the implementation, maybe it's a nonce reuse challenge like every other signature challenges out there? That we shall see later. First we need to understand how `schnorr signatures` actually work.

### Understanding `schnorr signatures`

{{< admonition type=success title="Note" open=true >}} This portion is heavily inspired from the wikipedia article on schnorr signatures. {{< /admonition >}}

This is a digital signaure method whose security lies on the classic `discrete logarithm` problem. Like any signaure scheme there is, the bigger picture is similar: one party signs a message `m` and the other party verifies whether the sign is authentic or not. 

Now before a message is signed, some parameters need to be generated. A group needs to be chosen with prime order $q$. This is important because there are different attacks (eg. pohlig hellman) when the group order is non-prime. A generator $g$ is chosen and agreed upon by both the parties involved. With the public parameters dealt with, next comes the key generation step. There are 2 keys involved: $x$, the private signing key and $y$, the public verifying key. Here $y = g^{-x}$. 

#### Message signing

Suppose we want to sign a message `m`. What we would basically do is:

* Start with generating a random value $k$.
* Set $r = g^{k}$
* Set $e = \text{H}(r || m)$ where $\text{H}$ denotes any hash function of choice with pre-image resistance and $||$ denotes string concatenation.
* Set $s = k + x \cdot e$

The generated pair $(s, e)$ is the required signature

#### Signature verification

We have $(s, e)$ pair from last step. To check if they are authentic or not, we do the following:

* Calculate $r' = g^{s} y^{e}$
* Calculate $e' = \text{H}(r' || m)$. 
  
If $e' = e$ only then can we say that the signature is indeed correct.

#### Proof of correctness

We need to wrap around our head as to why this verification works. 

$$
\begin{aligned}
r' &= g^s y^e \\\
  &= g^{k + xe} g^{-xe} \\\
  &= g^k \\\
  &= r
\end{aligned}
$$

And because of it, we can also write 

$$\begin{aligned}
e' &= \text{H}(r' || m) \\\
   &= \text{H}(r || m) \\\
   &= e
\end{aligned}$$

This concludes our proof.

### Understanding the given script

Equipped with the necessary background knowledge, we are now ready to tackle the given problem. 

#### Overview of the script

* The public parameters $p, q, g$ is generated from a function called `gen_snore_group` and provided to us.
* We need to pass 10 rounds where at each round what happens is:
    * The keys $x, y$ is generated and $y$ is given. 
    * We can send a message $m$ which will be signed using a function called `snore_sign` and the pair $(s, e)$ is given.
    * Note that any query that we make, it must be unique. Once a message $m$ is queried, we can never query for it again, not in this round, nor in any other rounds.
    * Now we need to peform a forgery and provide them with $m', s$ (ofcourse $m \not ={m'}$) such that the $e'$ generated due to $m'$ is equal to the previously given $e$. This is verified using a function called `snore_verify`.
* If we can pass all the rounds, we win and the flag is then given.

All right, it's a signature forgery problem! From my experience so far, problems of this type generally has some bugs in the implementation. That is what we are going to do now, go through functions one by one and check if there is some bug that we can exploit. 

#### `hash` function

Uses `SHA512` hashing but in a different way, kindof iterative approach. My hunch was that maybe there is length extension attack possible here? But no, upon futher inspection I understood it's not possible and the function is collision resistant.

#### `gen_snore_group` function

All the signature parameters are generated here. Maybe the prime generation is faulty and it has a smooth order? No, this uses very safe primes and so no such attack is possible.

#### `snore_gen` function

The keys are generated here. As usual, nothing faulty or suspicious thing is going on.

#### `snore_sign` function

$k, r$ is generated as it should be. But there is something suspicious going on in the generation of $e$. Here $e = \text{hash}((r + m) \mod p) \mod q$. Didn't we learn that $e = \text{hash}(r || m)$ ?? It is supposed to be **concatenation**, not **addition**. And this is exactly the bug in this problem that we are going to exploit in a while.

#### `snore_verify` function

All good except the same addition error in $e$ generation just like the last function. 

### Exploiting the bug

Remember what our goal was? We had to find two different messages (here integers) $m$ and $m'$ such that the signature they generate are the same. That is $(s, e) = (s', e')$. 

For the moment, let's just think about $e$. We need to find $m, m'$ such that $e = e'$. That is, we can write,

$$
\text{hash}((r + m) \mod p) \equiv \text{hash}((r + m') \mod p) \mod q
$$

We had $e = \text{hash}((r + m) \mod p) \mod q$ for a message $m$. What will happen for a message $m' = m + p$?

$$\begin{aligned}
e' &= \text{hash}((r+m') &\mod p) &\mod q \\\
   &= \text{hash}((r+m+p) &\mod p) &\mod q \\\ 
   &= \text{hash}((r+m) &\mod p) &\mod q  \ \ \ [(m + p) \mod p = m] \\\
   &= e 
\end{aligned}$$

Since $e'$ becomes the same as $e$, the $s'$ would become equal to $s$ as well, since it depends on $e$.
It means we can send any message $m' = m + l*p$ for any $l$ but get the same signature $(s, e)$. 

### Finishing off the exploit

For each round $i$, we send the messages $m = i$ and $m' = i + p$ and thus forging signaures easily!! For the signature $s$, we send the one we recieve from the oracle at that particular round.

```python
def connect():
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  context = ssl.create_default_context()
  ssl_sock = context.wrap_socket(sock, server_hostname='snore-signatures.chal.uiuc.tf')

  ssl_sock.connect(('snore-signatures.chal.uiuc.tf', 1337))
  return ssl_sock

sock = connect()
p = int(recvline(sock).decode().strip().split('= ')[1])
for _ in range(2):
  recvline(sock)

for m in range(10):
  for _ in range(2):
    recvline(sock)
  recvuntil(sock, b'= ')
  sendline(sock, str(m).encode())

  s = recvline(sock).decode().strip().split('= ')[1]
  for _ in range(2):
    recvline(sock)
  recvuntil(sock, b'= ')
  sendline(sock, str(m + p).encode())
  recvuntil(sock, b'= ')
  sendline(sock, s.encode())
  print(recvline(sock).decode())
  
print(recvline(sock).decode())
print(recvline(sock).decode())
```

> FLAG: **uiuctf{add1ti0n_i5_n0t_c0nc4t3n4ti0n}**

---
