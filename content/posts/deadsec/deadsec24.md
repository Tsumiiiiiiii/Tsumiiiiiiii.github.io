---
weight: 1
title: "Deadsec CTF 2024 - Raul Rosas writeup"
date: 2024-07-30T14:30:00+06:00
lastmod: 2024-07-30T14:30:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for Raul Rosas from DeadSec CTF 24."

tags: ["crypto", "DeadSec CTF", "RSA", "factorization", "bivariate coppersmith", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true

toc:
  enable: true
  position : "left"
---

Writeup for Raul Rosas from DeadSec CTF 24.


<!--more-->

Deadsec CTF is kinda significant to me because the last year's edition taught me LCGs (which later on helped me win 2 writeup prizes). This time I've managed to solve 
3 out of the 6 crypto challenges. Two of them were easy, but Raus Rosas was interesting. This post will be about that particular challenge.

## Overview of the given script

We are given with the following handout:

```python
from Crypto.Util.number import * 
from sympy import nextprime

p1 = bin(getPrime(1024))[2:]
p2 = p1[:605]
p2 = p2 + ('0'*(len(p1)-len(p2)))

p1 = int(p1,2)
p2 = nextprime(int(p2,2))

q1 = getPrime(300)
q2 = getPrime(300)

n1 = p1*p1*q1 
n2 = p2*p2*q2 

e = 65537 
flag = bytes_to_long(b'REDACTED')
c1 = pow(flag,e,n1)
c2 = pow(flag,e,n2)

print(f'{n1=}')
print(f'{n2=}')
print(f'{c1=}')
print(f'{c2=}')
```

This is basic multi prime RSA where two encryptions of the flag is given:

$$
\begin{aligned}
c_1 &= m^e \mod n_1 \\\
c_2 &= m^e \mod n_2 \\\
n_1 &= p_{1}^2 \* q_1 \\\
n_2 &= p_{2}^2 \* q_2
\end{aligned}
$$

But the primes seem to be generated in an *oddly specific* way.  The prime $p_1$ which is of $1024$ bits is generated normally using `getPrime` function. The catch is in the generation of $p_2$.  What happens is, the last $419$ bits (LSB) of $p_1$ is 0'd out. That is, $p_1' = (p_1 >> 419) << 419$, the lower $419$ bits of $p_1'$ is $0$. Then $p_2 = nextprime(p_1')$.  

Two other primes $q_1, q_2$ is generated which are both $300$ bits.

## Thinking of a solution

An important observation is that, most of the lower bits of $p_2$ will be $0$. This is because of how it was generated, remember it is the next prime of $p_1'$ and the next prime number is not far (maximum $2000$ difference). So out of the lower $419$ bits of $p_2$, the lowest $11$ bits might be non-$0$ and the remaining $408$ bit will be $0$. But the higher bits of $p_2$ is unknown. So we can write:

$$
p_2 = \underbrace{p_{hi}}\_{605 \ bits} \  | \underbrace{p_{lo}}\_{419 \ bits \ (mostly \ 0s)} 
$$

Or mathematically, this can be represented as, $p_2 = p_{hi} * 2^{419} + p_{lo}$. Where $p_{hi} \approx 2^{605}$ and $p_{lo} \approx 2^{11}$. Now why the bound for $p_{lo}$ is so small has already been explained (most of the bits are $0$). Lets, represent $p_{hi}$ as $x$ and $q_2$ as $y$ and then we can write $n_2$ as follows:

$$
\begin{aligned}
n_2 &= p_2^2 * q_2 \\\
    &= (x * 2^{605} + p_{lo})^2 * y 
\end{aligned}
$$

## `defund` for the win

We see that in the algebraic representation of $n_2$ above, both $x$ and $y$ are very small compared to the modulus $n_2$. This hints to a bi-variate coppersmith solution. So we can brute-force the values of $p_{lo}$ (only around $2000$ of them), and try to see if coppersmith returns a valid solution or not.  We can use [defund's script](https://github.com/defund/coppersmith) for solving the bivariate equation. But how to understand if the solution is valid or not? Suppose from the solution we get $p_2'$ and we don't know it it's correct one or not.  It will be correct if $\text{GCD}(p_2', n_2) > 1$. 

**BUT**, there is a slight problem here. Notice that the most trivial solution is$(x, y) = (0, 0)$ as that perfectly satisfies the equation for $n_2$.  This cost me around 2 to 3 hours to understand what was happening and fix it. We have to somehow force the solver to return us non-zero solutions. Notice that $q_2$ is a $300$ bit prime number. So the $299$th bit must be $1$. For this reason, instead of writing $q_2 = y$, we write $q_2 = 2^{299} + y$. Then $y$ will be bounded by $2^{298}$ and it also guarantees that trivial solutions would not be returned. 

## Finishing off the solution

I've used defunds script as a black box and adjusted my script accordingly. As previously explained, the bounds for $(x, y)$ is $(2^{605}, 2^{298})$. 

```python
from Crypto.Util.number import *
from sympy import nextprime
from tqdm import tqdm

n = 456...3
c2 =339...017

for p_lo in tqdm(range(1, 2000)):
    R = Integers(n)
    P.<x, y> = PolynomialRing(R)
    sz = 1024-605
    f = (x * (2^sz) + p_lo)^2 * (y + 2^299)
    bounds = (2^(1024-sz), 2^298)

    roots = small_roots(f, bounds)[0]
    p_hi = int(roots[0])
    p = p_hi*(2^sz) + int(p_lo)
    p = int(p)
    n = int(n)
    if GCD(p, n) > 1:
        print(p_lo)
        print(p)
        assert is_prime(p)
        q = n // (p*p)
        phi = p * (p - 1) * (q - 1)
        d = pow(65537, -1, phi)
        m = pow(c2, d, n)
        print(long_to_bytes(int(m)))
        break
```

This returns

```shell
  7%|▋         | 134/1999 [01:43<23:54,  1.30it/s]

135
166292923040204084265843130636698637584359774921220490721462725292059948122441620862133604226598302739069191920030887836407496935178966085862511815981684351701520622219816752182249648058443547518074081342679902265863213271998193281562912084447381292514071508413273157158843445022146713567281397262106520191111
b'DEAD{Rual_R0s4s_Chiweweiner!!}'
```

## Alternate solutions

### 🧀 (factordb)

Apparently people mentioned that they could find the factors for $n2$ right on [factordb](https://factordb.com). Very suspicious. Likely what happened was that someone factorized $n2$ using *legal* methods then uploaded on factordb. Things like this ruins the fun.

### Some clever observations

This solution was mentioned by [@ctfguy](ctfguy.github.io) in the discord server. 

$$\begin{aligned}
n_2 \mod 2^{400} &= (p_{hi} * 2^{609} + p_{lo}) ^ 2 * q_2 \mod 2^{400} \\\
			   &= p_{lo}^2 * q_2 \mod 2^{400}
\end{aligned}
$$

Here, the product is  small enough (around $322$ bits) so it remains unaffected by $\mod 2^{400}$. 

Since the sample space for $p_{lo}$ is very small ($2^{11}$ bits), we can enumerate them all, and whenever $(n_2 \mod 2^{400}) \mod p_{lo}^2 \equiv 0$, we have found the correct $p_{lo}$. This means, we can find $q_2 = (n_2 \mod 2^{400}) \ / \ p_{lo}^2$.  Once $q_2$ is found, we get $p_2 = \sqrt(n_2 \ / \ q_2)$. Thus the modulus is factored and we can do basic RSA decryption now to recover the flag.

                                                                                          
