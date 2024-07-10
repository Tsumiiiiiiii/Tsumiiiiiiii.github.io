---
weight: 1
title: "UIU CTF 2024 - snore signature and Key in a haystack writeup"
date: 2024-07-07T00:37:00+06:00
lastmod: 2024-07-07T00:37:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for some Cryptography challenges from UIU CTF 24."

tags: ["crypto", "UIU CTF", "schnorr", "signature forgery", "pollard p - 1", "factorization", "ecm", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true

toc:
  enable: true
  position : "left"
---

Writeup for some Cryptography challenges from UIU CTF 24.


<!--more-->

Solved all crypto problems (finally 😍) in this edition of UIU CTF. The problems were trivially easy, to be honest. For a CTF of this calibre, the difficulty curve should be more steep. To put things into perspective, the most difficult crypto challenge (`Key in a haystack`) had more than 60 solves. I think the 22nd edition was perfect in terms of balanced difficulty. Nevertheless, the problems were still refreshing and fun to try. Here, I will make writeups for two challenges: `snore signature` and `Key in a haystack`.

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

Now before a message is signed, some parameters need to be generated. A group needs to be chosen with prime order $q$. This is important because there are different attacks (eg. pohlig hellman) when the group order is non-prime. A generator $g$ is chosen and agreed upon by both the parties involved. 

With the public parameters dealt with, next comes the key generation step. There are 2 keys involved: $x$, the private signing key and $y$, the public verifying key. Here $y = g^{-x}$. 

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

#### `snore_sign` function 🤔

```python {linenos=table,hl_lines=[4],linenostart=1}
def snore_sign(p, q, g, x, m):
    k = randint(1, q - 1)
    r = pow(g, k, p)
    e = hash((r + m) % p) % q
    s = (k + x * e) % q
    return (s, e)
```

$k, r$ is generated as it should be. But there is something suspicious going on in the generation of $e$. Here $e = \text{hash}((r + m) \mod p) \mod q$. Didn't we learn that $e = \text{hash}(r || m)$ ?? It is supposed to be **concatenation**, not **addition**. And this is exactly the bug in this problem that we are going to exploit in a while.

#### `snore_verify` function 🤔

```python {linenos=table,hl_lines=[5],linenostart=1}
def snore_verify(p, q, g, y, m, s, e):
    if not (0 < s < q):
        return False
    rv = (pow(g, s, p) * pow(y, e, p)) % p
    ev = hash((rv + m) % p) % q

    return ev == e
```

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

For each round $i$, we send the messages $m = i$ and $m' = i + p$ and thus forging signaures easily!! For the signature $s$, we send the same one recieved from the oracle at that particular round.

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

## Key in a haystack

The given code is very short and to the point

```python
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

from hashlib import md5
from math import prod
import sys

from secret import flag

key = getPrime(40)
haystack = [ getPrime(1024) for _ in range(300) ]
key_in_haystack = key * prod(haystack)

enc_flag = AES.new(
	key = md5(b"%d" % key).digest(),
	mode = AES.MODE_ECB
).encrypt(pad(flag, 16))

sys.set_int_max_str_digits(0)

print(f"enc_flag: {enc_flag.hex()}")
print(f"haystack: {key_in_haystack}")

exit(0)
```

A short prime of 40 bits is generated and used as the key for `AES-ECB` encryption. Then 300 huge primes of 1024 bits are generated. They are multiplied along with the key and given to use. So what we have is basically

$$
haystack = key \prod_{i = 1}^{300} p_i
$$

Our goal is to recover the $key$ prime somehow. This ultimately boils down to a factorization problem. We can solve this problem in 2 ways and I am going to explain them both here. 

### First method : using some observations and `ECM` (unintended)

This is the method that I followed during the CTF. My first idea was to put the huge product on [alpetron ECM factorization](https://www.alpertron.com.ar/ECM.HTM), but soon I discarded this idea as the product was too large ($307240$ bits) and maybe it can't work with such big numbers? Though someone on discord later said that this would have worked (takes around 3 hours though). 

Anyway, I was playing with the code when an interesting observation was found.

```python
key = getPrime(40)
haystack = [ getPrime(1024) for _ in range(300) ]
key_in_haystack = key * prod(haystack)
```

This particular code snippet took around 5 minutes to run on `google colab`. But when I connected on remote, it prints the product almost instantly. How is that even possible? Not like the admins have access to some super secret quantum computers (at least I hope they don't!) that they will generate so many big primes within a few seconds. So there must be some optimization going on in the background? 

There was a CTF I once played where they optimized this by pre-generating a big pool of primes and randomly sampling from that pool. Maybe the author did the same thing here? I wanted to test my hypothesis. 

How can this test be done? So if the pre-generated pool is not that big, then it is very likely that the same primes would be reused in the `haystack`. We make 50 connections to remote and collect 50 `haystack` samples. We have $haystack_1, haystack_2, \cdots, haystack_{49}, haystack_{50}$. If they share same primes, then for any random $i, j$, $\text{GCD}(haystack_i, haystack_j)$ is supposed to be more than 1 with high probability(?). Using below script we check this count:

```python
def get_stuff():
  sock = connect()

  for _ in range(3):
    recvline(sock)

  pow = solve_challenge(recvline(sock).decode().strip().split()[-1])

  recvline(sock)
  sendline(sock, pow.encode())
  for _ in range(2):
    recvline(sock)

  enc = recvline(sock).decode().strip().split()[-1]
  
  haystack = int(recvline(sock).decode().strip().split()[-1])
  return enc, haystack

sys.set_int_max_str_digits(0)
haystacks = []
encs = []
for _ in tqdm(range(50)):
  enc, haystack = get_stuff()
  haystacks.append(haystack)
  encs.append(enc)

for i in range(50):
  cnt = 0
  for j in range(50):
    if i != j:
      g = int(gmpy2.gcd(haystacks[i], haystacks[j]))
      if g > 1:
        cnt += 1
  print(cnt, end = ' ')
```

The output is:

```bash
100%|██████████| 50/50 [01:41<00:00,  2.03s/it]
49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49 49
```

Well... literally all the 50 samples share at least one prime with all other samples!. Is this normal? What are the chances(I mean probaility) for this to happen if the primes were generated at random? 

Time for some math lessons. From the [prime number theorem](https://en.wikipedia.org/wiki/Prime_number_theorem) we can approximate the number of primes within a certain bound $N$. The value is given by,

$$
\pi(N) \approx \frac{N}{\ln(N)}
$$

Here we have $N = 2^{1024}$ and so the bound is in the range of $\frac{2^{1024}}{\ln{2^{1024}}} \approx 2^{1015}$. That number is honestly quite large 😫 . 

Suppose we pick two haystack samples at random. What is the probability that they share at least 1 prime factor in common?

$$\begin{aligned}
&\text{P(two haystacks share at least one prime factor)} \\\
&= 1 - \text{P(two hastacks share no prime factor)} \\\
&= 1 - \frac{\binom{N}{300} \binom{N-300}{300}}{\binom{N}{300}^2} \\\
&= 1 - \frac{\binom{N-300}{300}}{\binom{N}{300}}
\end{aligned}
$$

Putting the value of N, python gave me the probability to be $5e^{-304}$. This value is extremely extremely extremely extremely .... small.  Honestly, the probability that I'm going to be selected for a PhD position at UIU is much much much higher than that 😃. Which means, that if the primes were generated at random, there is practically no chance that any 2 haystacks would have a prime in common. This proves that the pool of primes the author precalculated is not so big.

Using this fact, we can weed out the large prime factors one by one by taking `GCD`. Since every hastack has something in common with the other samples, we can keep on dividing a haystack by the common factors it has with every other haystacks. In this way, we try to reduce each haystack as much as possible. 

```python
sz = 1000000000
idx, res = 0, 0
for i in range(50):
  x = haystacks[i]
  for j in range(50):
    if i != j:
      g = int(gmpy2.gcd(x, haystacks[j]))
      x //= g
  sz_ = x.bit_length()
  if sz_ < sz:
    sz = sz_
    idx = i
    res = x
print(sz)
```

We get an output of $14373$. This is a significant reduction of size. Maybe alpetron is fast enough to factor is? We can try our luck. And voila, after around 3 minutes, it spits out the $key$! Alpetron uses a method called `ECM`. I honestly have no idea how that works, except the fact that it uses `elliptic curves` somehow :3

### Second method : pollard's $p - 1$ factorization (intended)

Everyone who plays CTF at least once have heard of this factorization method. Eventhough I knew this method for like 2 years, for some reason I didn't bother learning why or how it works :sad. Thanks to this problem I finally had the push to dive into it. 

Let us assume the problem setting is `RSA` with $N = p \cdot q$. Our job is to recover $p, q$. The said factorization holds when either or both the primes are $B$ power-smooth. What does this mean? 

Before we understand the term power-smooth, let's see what $B$ smooth means. It means that the factors of $p-1$ are all smaller than $B$. That is, $p-1 = f_1 \cdot f_2 \cdot f_3 \cdots f_n \ \ \forall f_i < B$. 

Power-smooth is a concept closely related to this. We will call a prime $p$ to be $B$ power-smooth if the following holds:

$$p - 1 = f_{1}^{e_{1}} \cdot f_{2}^{e_{2}} \cdot f_{3}^{e_{3}} \cdots f_{n}^{e_{n}} \quad \text{where} \quad f_{i}^{e_{i}} < B . $$

Now, we know from `fermat's little theorem` that, for a prime $p$ and for an integer $a$ where $a$ is co-prime to $p$,

$$\begin{aligned}
a^{p-1} &= 1 \mod p \\\
\implies a^{p-1} - 1 &= 0 \mod p \\\
\implies a^{p-1} - 1 &= lp
\end{aligned}$$

That means $\text{GCD}(a^{p-1} - 1, N) = p$. Note that due to fermat, $a^{k(p-1)} = 1 \mod p$ also holds, and so $\text{GCD}(a^{k(p-1)} - 1, N) = p$. Why is $k$ relevant here? Because if we raise an arbitrary $a$ (wich is co-prime to $N$ ay $a = 2$) to a huge power where the power is a multiple of $p-1$, we increase the likelihood to get one of the prime factors as `GCD`. Generally the power we raise is chosen to be product of all prime powers smaller than $B$ (let's call it $x$) and check if $\text{GCD}(a^x - 1, N) > 1$. If not, $x$ is increased and checked again. 

It's better to explain with an example. Suppose $N = 299$. Let the bound $B = 5$. So we need to consider prime powers for the primes $2, 3, 5$.  Here $2^2 < B, 3^1 < 5, 5^1 \le 5$. So we take $x = 2^2 * 3^1 * 5 ^ 1$. $a = 2$ is chosen and here $\text{GCD}(a^x - 1, N) = \text{GCD}(2^{60} - 1, 299) = 13$. Voila! we have recovered one of the prime factors. We can recover the other one by $N / 13 = 23 $.

The algorithm can be formally written as follow:

1. We select a smoothness bound $B$.
2. Define $x = \prod_{primes p \le B}^{} p ^ {\lfloor \log_{q}^{B} \rfloor}$. This $log$ ensures the powe-smoothness.
3. Choose a co-prime $a$. Normally it's same to pick $a = 2$ since that prime itslef is never chosen. 
4. Calculate $g = \text{GCD}(a^x - 1, N)$
5. If $1 < g < N$, we have found one of the prime factors. Return the value.
6. If $g = 1$, we do $x \leftarrow x + 1$.
7. Else if $g = N$, we do $x \leftarrow x - 1$. 

With the algorithm explained and understood, it's now time to see how this algorithm is relevant in the context of the given problem. Remember the problem setup was like this: $haystack = key \cdot p_1 \cdot p_2 \cdots p_{300}$. We have to recover the 40 bit $key$. The concept of smoothness can be used here here. Maybe the key is some $B$ power-smooth where $B$ is reasonably small? If the bound $B$ is bigger, the probability is more that the prime is $B$ smooth. 

But there is a tradeoff here, the more we increase the bound, the more costly it becomes. We can't afford so much time for a probabilistic solution. So we have to use a reasonably smaller bound so that it doesn't become too costly, and also there is good chance to be smooth. Somethin like 17 to 18 bits should be good enough. Shouldn't take more than a few mintues. 

The pollard algorithm implemention should be a bit different than the usual one. This is because we are estimating the bounds. It might be the case that we are severerly underestimating. Say we estimated the bound to be of 15 bits when the actual bound was 25 bits. So if we use the original algorithm, it would keep on running for a long time (step 6 of the algorithm) until B reaches 25 bits from 13 bits. That's why it's better to keep a limit to the number of iterations it can run (say $1000$ iterations should be good enough). If it fails to return a solution within this time, we consider that the bound was actually much higher. So we close that connection, open a new one (and pray that this time the prime is $B$ smooth). After a few connections, we get  such a case, and hence, get the key!

> FLAG: **uiuctf{Finding_Key_Via_Small_Subgroups}**
