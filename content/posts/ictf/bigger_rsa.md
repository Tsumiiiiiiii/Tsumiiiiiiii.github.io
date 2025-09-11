---
weight: 1
title: "Imaginary CTF 25 - Writeup for Bigger RSA crypto challenge"
date: 2025-09-10T17:30:00+06:00
lastmod: 2024-09-10T17:30:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Factoring RSA modulus with a setup similar to the Approximate Common Divisor problem"

tags: ["crypto", "ictf", "AGCD", "LLL", "RSA", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true
  
---

The following sage script is given to us,

```python=
from Crypto.Util.number import getPrime, bytes_to_long
import secrets

n = 32
e = 0x10001
N = 64

flag = b'ictf{REDACTED}'
flag = secrets.token_bytes((n * 63) - len(flag)) + flag

ps = [getPrime(512) for _ in range(n)]

m = 1
for i in ps:
    m *= i

nums = [CRT([1 + secrets.randbits(260) for _ in range(n)],ps) for __ in range(N)]
ct = pow(bytes_to_long(flag),e,m)
print(f"ct={ct}")
print(f"m={m}")
print(f"nums={nums}")
```

This is a many-prime RSA setup, with 32 primes forming the modulus. Apart from the ciphertext and the modulus, we are also given a sort of "hint", called nums. It is important to understand the structure of these hints,

$$
\begin{aligned}
nums_1 & = \text{CRT}([x_{1, 1}, x_{1, 2}, \dots, x_{1, 32}], [p_1, p_2, \dots, p_{32}]) \\\
nums_2 & = \text{CRT}([x_{2, 1}, x_{2, 2}, \dots, x_{2, 32}], [p_1, p_2, \dots, p_{32}]) \\\
\vdots \\\
nums_{64} &= \text{CRT}([x_{64, 1}, x_{64, 2}, \dots, x_{64, 32}], [p_1, p_2, \dots, p_{32}]) \\\
\end{aligned}
$$

Here, CRT denotes the  chinese remainder theorem. Also, it's crucial to note than the $x$'s are small, i.e. $x_{i,j} \approx 2^{260}$ compared to the primes($p_i \approx 2^{512}$). 

It might be helpful to write the equations for CRT to better plan ahead. For the rest of this writeup, assume it's a 4 prime setup instead of the given 32. The hints can basically be represented as,

$$
\begin{aligned}
num = \ &  x_1 \cdot (p_1\*p_2\*p_3) \cdot [(p_1\*p_2\*p_3) ^{-1} \mod p_4]&& + x_2 \cdot (p_1\*p_2\*p_4) \cdot [(p_1\*p_2\*p_4) ^{-1} \mod p_3] \\\
  & x_3 \cdot (p_2\*p_3\*p_4) \cdot [(p_2\*p_3\*p_4) ^{-1} \mod p_1] && + x_4 \cdot (p_1\*p_3\*p_4) 
 \cdot [(p_1\*p_3\*p_4) ^{-1} \mod p_2] 
\end{aligned}
$$

What happens if we mod this equation by the respective primes?

$$
\begin{aligned}
num & \equiv x_1 && \mod p_4 \\\
num & \equiv x_2 && \mod p_3 \\\
num & \equiv x_3 && \mod p_1 \\\
num & \equiv x_4 && \mod p_2 \\\
\end{aligned}
$$

If we take the first equation, we can write,

$$
\begin{aligned}
& num && + k_1\cdotp_4 = x_1 \\\
\rightarrow \ & num && + k_1 \cdot (m / (p_1\*p_2\*p_3)) = x_1 \\\
\rightarrow \ & num \cdot(p_1\*p_2\*p_3) &&+ k_1\cdot m = x_1 \cdot (p_1 \* p_2 \* p_3) \\\
\rightarrow \ & num \cdot q_4 &&+ k_1\cdot m = x_1 \cdot q4 
\end{aligned}
$$

Here $q_i = m / p_i$.

Notice that the right hand side of this equation is smaller than n by 250ish bits, thanks to the small $x$. And a small output such as that leads to lattices. Since we have multiple such nums, we have $num_i \cdot q_4 + k_i \cdot m = x_{i, 1} \cdot q_4$

$$
q_4
\begin{bmatrix}
num_{1} \\\ num_{2} \\\ \vdots \\\ num_{n} \\\ 1
\end{bmatrix}
+k_1
\begin{bmatrix}
m \\\ 0 \\\ \vdots \\\ 0 \\\ 0
\end{bmatrix}
+k_2
\begin{bmatrix}
0 \\\ m \\\ \vdots \\\ 0 \\\ 0
\end{bmatrix}
+k_n
\begin{bmatrix}
0 \\\ 0 \\\ \vdots \\\ m \\\ 0
\end{bmatrix}
=\\
\begin{bmatrix}
q_4 \cdot x_{1,1} \\\ q_4 \cdot x_{2,1} \\\ \vdots \\\ q_4 \cdot x_{n,1} \\\ q_4
\end{bmatrix}
$$

{{< admonition type=alert title="Some notes" open=true >}} In the actual instance, its important to use flatter, as the basis becomes very huge. And while using flatter, 
its ideal to make all the entries in the ouput vector have the same length, 
so we multiply the bottow row by 2^260, giving us [q\*x_1, q\*x_2,..., q\*2^260]. {{< /admonition >}}

Reducing this basis gives us $q_4$, and in turn $p_4$. 

We have recovered one factor so far, and by how the problem has been set, we have to recover the other 3 primes as well. It is not so difficult, as we can repeat the similar process as before. We reduce each hint modulo $q_4$ i.e. $num'_i = num_i \mod q_4$. This is repeated until m is fully factored.

```python!

def get_primes(L):
    st = set()
    for row in L:
        num = int(abs(row[-1]))
        if num != m and num!= 0:
            num = gcd(num, m)
            g = m // num
            st.add(g)
                
    v = list(st)
    sz = len(v)
    st = set()
    for a in range(sz):
        for b in range(a + 1, sz):
            g = gcd(v[a], v[b])
            if is_prime(g):
                st.add(g)
    return list(st)

n = m
    
primes = set()
updated_nums = nums
while True:
    if m == 1:
        break
        
    if is_prime(m):
        primes.append(m)
        break
    
    updated_nums = [num % m for num in updated_nums]
    mat = (
            Matrix(updated_nums)
            .T
            .augment(diagonal_matrix([m]*N))
            .stack(vector([2^260] + [0]*N))
            .T
    )
    
    print('will do LLL now')
    L = flatter(mat)
    print('LLL done')
    stuff = get(L)
    print(f'Found {len(stuff)} primes??')
    for s in stuff:
        if m % s == 0:
            m = m // s
        primes.add(s)
    print(f'current size of primes is {len(primes)}')
```

Thanks to @ConnorM for helping me understand how the lattice works here. 
