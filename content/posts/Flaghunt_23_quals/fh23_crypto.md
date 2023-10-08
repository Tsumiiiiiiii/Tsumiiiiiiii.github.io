---
weight: 1
title: "FlagHunt 2023 quals - My Crypto Writeup"
date: 2023-10-8T15:02:00+06:00
lastmod: 2023-10-8T15:20:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for the cryptography problems that I designed."

tags: ["crypto", "FlagHunt", "RSA", "Quadratic-Residue", "CRT", "gcd-attack", "english"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---

Writeup for the Ice cream generator Cryptography challenge.

<!--more-->

## Overview

Given that guessy and cipher-based cryptography challenges are way too common in Bangladeshi CTFs, my goal was to introduce problems that require mathematics and algorithms, something that requires 
actual problem-solving, not hours of boring guesswork that we all despise.

It was quite surprising to see so many solves for `baby_RSA` though😲, given it was quite difficult. And that too at like around the last 30 minutes of the CTF 🤔. I wish I too had such ideas keep coming to me at the very last moment when I'm playing CTFs 😟. 

## Chances

{{< admonition note "Challenge Information" >}}
* **Points:** 100

{{< /admonition >}}

Let us go through the given script
```python
from random import randint

flag = open('flag.txt', 'rb').read()

def to_bits(c):
    b = bin(c)[2:]
    while len(b) != 8:
        b = '0' + b
    return b

bits = ''.join([to_bits(c) for c in flag])

distorted = []

for _ in range(50):
    d = ''
    for b in bits:
        r = randint(1, 10)
        if r <= 3:
            b = int(b) ^ 1
        d += str(b)
    distorted.append(d)
 
with open('out.txt', 'w') as f:
    to_write = '\n'.join(distorted)
    f.write(to_write)
```

We can see that the same message is passed through a noise function 50 times. What the noise does it, it takes a bit, and with 30% probability, that bit is flipped. Luckily, we have enough samples to recover the correct bit at each position. 

We can represent the distorted list as a matrix, where each entry represents a bit. The bit $a_{i,j}$ represents the bit numbered `j` at the message no. `i` . 

$$
A_{m,n} = 
\begin{bmatrix}
a_{1,1} & a_{1,2} & \cdots & a_{1,n} \\\
a_{2,1} & a_{2,2} & \cdots & a_{2,n} \\\
\vdots  & \vdots  & \ddots & \vdots  \\\
a_{m,1} & a_{m,2} & \cdots & a_{m,n} 
\end{bmatrix}
$$ 

Now, what does a particular column in this matrix represent? 

$$
A_{k} = 
\begin{bmatrix}
a_{1,k} \\\
a_{2,k} \\\
\vdots \\\
a_{m,k}  
\end{bmatrix}
$$

The `k-th` column represents all the bits that are in position `k` of the message. According to the problem formulation, around 70% of these bits would be correct, and so, the remaining 30% bits are incorrect. How do we know which bits are correct? 

What I claim is, we can just note down which bit has more occurrences than the other, and that would be the correct bit. Since the correct bit will be have around 70% occurrences, it's trivial to understand why my claim stands. 

Let

$$cnt_{0, k} = number \ of \ 0 \ bits \ in \ column \ k$$
$$cnt_{1, k}= number \ of \ 1 \ bits \ in \ column \ k$$



Then the `k-th` bit of the message will be

$$
bit_k=
\begin{cases}
1 & cnt_{1,k} > cnt_{0, k}\\
0 & otherwise
\end{cases}
$$

Now with all the math done, we are ready to code our solution.

```python
corr_bits = ''

distorted = open('out.txt', 'r').read().split('\n')
sz = len(distorted[0])

for pos in range(sz):
    cnt0, cnt1 = 0, 0
    for i in range(50):
        if distorted[i][pos] == '0':
            cnt0 += 1
        else:
            cnt1 += 1
    if cnt0 > cnt1:
        corr_bits += '0'
    else:
        corr_bits += '1'

flag = ''
for i in range(0, len(corr_bits), 8):
    c = corr_bits[i: i + 8]
    flag += chr(int(c, 2))
    
print(flag)
```

> Flag: **CTF_BD{what_are_the_chances_heh??}**


## Square-root

{{< admonition note "Challenge Information" >}}
* **Points:** 225

{{< /admonition >}}

The problem script is quite short and straightforward. 
```python
from Crypto.Util.number import long_to_bytes as l2b, getPrime, bytes_to_long as b2l, inverse

flag = open('flag.txt', 'rb').read()
x = b2l(flag)

p = getPrime(1024)
a, b, c = getPrime(128), getPrime(128), getPrime(128)

y = (a*(x**2) + b*x + c) % p
with open('out.txt', 'w') as f:
    f.write(f"p = {p}\n")
    f.write(f"a = {a}\n")
    f.write(f"b = {b}\n")
    f.write(f"c = {c}\n")
    f.write(f"y = {y}\n")
```
We are given a quadratic polynomial of the form

$$ y \ = \ ax^2 + bx + c \mod p$$

This could be a very trivial problem, had there been no modulo operations involved. In that case we could have solved this problem with simple quadratic solvers. But what's the fun in that? ':3

How do we solve modular quadratic polynomails? Something called `quadratic residues` comes into play here. It solve problems of the type

$$ Y \ = \ X^2 \mod \ p$$

where the value of Y and p is known. `tonelli shanks` is a very powerful algorithm which can solve such equations for us.  But first, let us manipulate the given equation into something simpler which can be solved directly using `tonelii shanks`. 

$$ y \ = ax^2 + bx + c \mod p$$

$$ \Rightarrow \frac{y}{a} \ = \ x^2 + \frac{b}{a}x + \frac{c}{a} \mod p$$

$$ \Rightarrow \frac{y}{a} \ = \ x^2 + 2x\frac{b}{2a} + (\frac{b}{2a})^2 - (\frac{b}{2a})^2 + \frac{c}{a} \mod p$$

$$ \Rightarrow \frac{y}{a} - \frac{c}{a} + (\frac{b}{2a})^2 \ = (x + \frac{b}{2a})^2 \mod p$$

The above equation is enough to work with now, where we can write

$$ Y \ = \ \frac{y}{a} - \frac{c}{a} + (\frac{b}{2a})^2 \mod \ p $$

$$ X \ = \  x + \frac{b}{2a} \mod p$$

**By the way, do note that all divisions shown here are modular multiplication done with inverses.**
And so, we now have the form that was mentioned earlier

$$ Y \ = \ X^2 \mod \ p$$

The solution script is as follows
```python
from Crypto.Util.number import long_to_bytes as l2b, getPrime, bytes_to_long as b2l, inverse

p = 159117138695601086935648462476725143896981591038416901486093706070754873563937272793294757366059667782136312013577603110660003394277897367203934519905683172161079448635248857040486200482627367334414675502994685936812333774063439076898281362682381888787053539531164627370506379676784327677612773681859553362469
a = 183170230465848410077175594145038110799
b = 177960951503783858139483105160729532851
c = 241771663291314104599898559749454094799
y = 81883801483428304918741984834363388238539421922474300691841915944763281416203781633389084991872486015041884084357260412052258732056118424392145242000539134316390251752292462492913837148154805999331901388735321855253311517735430229163344305926114721299791844599487270387540543138183327842649901510556454592197

inv = inverse(a, p)
inv2 = inverse(2*a, p)

t1 = (y * inv) % p
t2 = (c * inv) % p
t3 = (b * inv2) % p
t3 = (t3 * t3) % p
k = (b * inv2) % p

y = (t1 - t2 + t3 + p) % p

# I googled for tonelli shanks implementation and this one came first
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
    
s = tonelli(y, p) - k
if s < 0 : s += p
print(l2b(s))
```

> Flag: CTF_BD{the_last_problem_had_a_bug_so_here_you_go_ABF123451D!}


## baby-RSA

{{< admonition note "Challenge Information" >}}
* **Points:** 225
  
`nc 45.76.177.238 5001`

{{< /admonition >}}

The problem can be summarized in two parts. The first part is applying the **GCD attack** twice to recover two pairs of `(message_reduced, modulus)`. Then those pairs are used in **Chinese Remainder Theorem** to find the actual `message`. 

Let us analyze the server script.
```python
#!/usr/local/bin/python
from Crypto.Util.number import getPrime, bytes_to_long as b2l, long_to_bytes as l2b

print("Welcome to delphi's query service!!")

primes = [getPrime(512) for _ in range(10)]

with open('flag.txt', 'rb') as f:
    flag = f.read()
    
m = b2l(flag)
assert(m.bit_length() > 1200 and m.bit_length() < 2000)

used_indices = set()
for _ in range(5):
    print('Enter 2 indices for primes to be used for RSA (eg. 0 4): ')
    i, j = map(int, input().split())
    if i in used_indices or j in used_indices or i < 0 or j < 0 or i == j:
        print('Illegal values given!!')
        exit(2)
        
    i, j = i % 10, j % 10
    
    used_indices.add(i)
    used_indices.add(j)
    
    p, q = primes[i], primes[j]
    n = p * q
    e = 0x10001
    
    ct = pow(m, e, n)
    print('n = ', n)
    print('ct = ', ct)
```

We see that the server initially generates 10 primes that are 512 bits each. Then we can interact with the server 5 times. Each interaction is of the following type : we give the server 2 indices `i, j` and the server uses $primes_i$ and $primes_j$ to use as primes for RSA to encrypt our flag. 

There is a catch though, we can't reuse any indices. Nor can we use negative indices. What benefit would have negative indices given us anyway? We know that negative indices wraps around the list in python, that is, for an array of size `n`, the index `-k` actually denotes the index `n - k`.  In that way we can reuse indices in our query. 

But is that the only way we can reuse indices? There is no checking in our code whether `i > n`. Rather the input is taken modulo `n`. In that way, we can reuse the same index `i` using `i` and `i + n` since both of them becomes `i` when reduced by `n`. 

Now that we understand how to use the same prime in two different queries, how does that help us? It helps us to factorize the RSA modulus. Let's say we use the following queries: `0 1` and `11 2`. The second query actually translates to `1 2` after being reduced modulo `n`. 

$$ n_1 = primes_0 * primes_1$$

$$ n_2 = primes_1 * primes_2$$

If we take the `GCD` of those two modulus, we get $primes_1$. 

$$ GCD(n_1, n_2) = GCD(primes_0 * primes_1, \ \ primes_1 * primes_2) = primes_1$$

Using $primes_1$, we can factorize both $n_1$ and $n_2$.  With the RSA modulus being cracked, we can now easily recover our flag ^^.

To spoil the mood, you would actually get a gibberish. Notice the following line in our server script:

```python
assert(m.bit_length() > 1200 and m.bit_length() < 2000)
```

Our RSA modulus is of 1024 bits. It means there will be losses of bits, that is, we would actually get `flag % modulus` instead of the original `flag`. That is why you got gibberish. 

What can we do in this situation? We need a modulus that is greater than 2000 bits. `Chinese Remainder Theorem` is the way to go. If we use the following pair in our `CRT`, 

$$reducedMessage_1 = flag \mod modulus_1$$

$$reducedMessage_2 = flag \mod modulus_2$$

`Chinese Remainder Thoerem` will combine the two modulus and give us a 2048 bits modulus. We are going to get $flag \mod modulus_1 * modulus_2$. This is enough as the new modulus (which is the product of previous two modulus) is more than the upper limit of flag size. 

With the idea ready at hand, the solution script can be coded easily. 

```python
from functools import reduce
from pwn import *
from Crypto.Util.number import long_to_bytes as l2b, GCD, isPrime

io = remote('45.76.177.238', 5001)

io.recvline()
io.recvline()
io.sendline(b'0 1')

n1 = int(io.recvline().decode().strip().split('= ')[1])
ct1 = int(io.recvline().decode().strip().split('= ')[1])

io.recvline()
io.sendline(b'11 2')

n2 = int(io.recvline().decode().strip().split('= ')[1])
ct2 = int(io.recvline().decode().strip().split('= ')[1])

io.recvline()
io.sendline(b'3 4')

n3 = int(io.recvline().decode().strip().split('= ')[1])
ct3 = int(io.recvline().decode().strip().split('= ')[1])

io.recvline()
io.sendline(b'14 5')

n4 = int(io.recvline().decode().strip().split('= ')[1])
ct4 = int(io.recvline().decode().strip().split('= ')[1])

print('[+] Params collection done')

def crack(N1, N2):
    p1 = GCD(N1, N2)
    p2 = p1
    q1 = N1 // p1
    q2 = N2 // p2
    assert(isPrime(p1) and isPrime(p2)  and isPrime(q1) and isPrime(q2))
    phi1, phi2 = (p1 - 1) * (q1 - 1), (p2 - 1) * (q2 - 1)
    e = 0x10001
    d1, d2 = pow(e, -1, phi1), pow(e, -1, phi2)
    return d1, d2

d1, d2 = crack(n1, n2)
m1, m2 = pow(ct1, d1, n1), pow(ct2, d2, n2)

d3, d4 = crack(n3, n4)
m3, m4 = pow(ct3, d3, n3), pow(ct4, d4, n4)

print('[+] Cracking done.. Will start doing the CRT')

def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * pow(p, -1, n_i) * p
    return sum % prod

def mul_inv(a, b):
    return pow(a, -1, b)

msg = chinese_remainder([n1, n3], [m1, m3])
flag = l2b(msg)
print(flag)
```

> Flag : **CTF_BD{i_made_this_flag_purposefully_bigger_so_that_u_are_forced_to_use_the_chinese_remainder_theorem_otherwise_it_would_be_too_easy_if_it_was_just_the_gcd_attackxD}**




