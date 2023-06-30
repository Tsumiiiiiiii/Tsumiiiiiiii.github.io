---
weight: 1
title: "angstrom CTF 2023 - Lazy Lagrange"
date: 2023-06-30T11:37:00+06:00
lastmod: 2023-06-30T11:37:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for the Lazy Lagrange Cryptography challenge."

tags: ["crypto", "angstrom CTF", "meet-in-the-middle", "english"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---

Writeup for the Lazy Lagrange Cryptography challenge.

<!--more-->

## Overview

Angstrom is without a doubt my favorite CTF competition. The problems are of high quality, and I learn a lot every time I solve a challenge. This year's competition was no different.

I played with my default team IUT GENESIS and managed to solve 6/8 Cryptography challenges. Although millionaires was the most difficult challenge I solved, lazy lagrange was which I enjoyed the most solving.

So I'll be making a writeup for lazy lagrange(also because I'm too lazy to make writeups🤡).

## The challenge

{{< admonition note "Challenge Information" >}}
* **Points:** 70
* **Description:** Lagrange has gotten lazy, but he's still using Lagrange interpolation...or is he?

`nc challs.actf.co 32100`

[lazylangrange.py](https://files.actf.co/374e6c15604b18ae93ce897a5710b113d40e81c19feea779fe5e7bf19f5a047c/lazylagrange.py)

{{< /admonition >}}

Note that the intended solution for this problem was much simpler and intuitive. I somehow missed that observation during the contest and opted for a meet-in-the-middle solution instead

Before I go to my solution, I would explain some approaches that I tried and why they failed. This is the code that we were provided with
```python

#!/usr/local/bin/python
import random

with open('flag.txt', 'r') as f:
	FLAG = f.read()

assert all(c.isascii() and c.isprintable() for c in FLAG), 'Malformed flag'
N = len(FLAG)
assert N <= 18, 'I\'m too lazy to store a flag that long.'
p = None
a = None
M = (1 << 127) - 1

def query1(s):
	if len(s) > 100:
		return 'I\'m too lazy to read a query that long.'
	x = s.split()
	if len(x) > 10:
		return 'I\'m too lazy to process that many inputs.'
	if any(not x_i.isdecimal() for x_i in x):
		return 'I\'m too lazy to decipher strange inputs.'
	x = (int(x_i) for x_i in x)
	global p, a
	p = random.sample(range(N), k=N)
	a = [ord(FLAG[p[i]]) for i in range(N)]
	res = ''
	for x_i in x:
		res += f'{sum(a[j] * x_i ** j for j in range(N)) % M}\n'
	return res

query1('0')

def query2(s):
	if len(s) > 100:
		return 'I\'m too lazy to read a query that long.'
	x = s.split()
	if any(not x_i.isdecimal() for x_i in x):
		return 'I\'m too lazy to decipher strange inputs.'
	x = [int(x_i) for x_i in x]
	while len(x) < N:
		x.append(0)
	z = 1
	for i in range(N):
		z *= not x[i] - a[i]
	return ' '.join(str(p_i * z) for p_i in p)

while True:
	try:
		choice = int(input(": "))
		assert 1 <= choice <= 2
		match choice:
			case 1:
				print(query1(input("\t> ")))
			case 2:
				print(query2(input("\t> ")))
	except Exception as e:
		print("Bad input, exiting", e)
		break
```
## Some failed approaches

This is a classic interpolation problem(almost). The 18 characters of the flag ($a_0, a_1, a_2, .., a_{16}, a_{17}$) are used as coefficients of a 17 degree polynomial like this:
$$a_0 + a_1x + a_2x^2 + a_3x^3 + a_4x^4 + ... + a_{16}x^{16} + a_{17}x^{17} $$
All too simple, if we could just get values at 18 points. But there is a catch, we can get values at maximum of 10 points from each ```query1```. That too would not have been a problem, we could have just obtained the remaining 8 points from a second call to ```query1```. What makes this approach infeasible, is that everytime we call ```query1```, the co-efficiets are randomly
shifted and so we get a different polynomial each time.

I wrote a script for ```query1('0')``` to check what are the characters of my flag. ```quer1('0')``` means the $a_0$ of the polynomial, which gives us the first character of the permutation. Running it a few hundred times ensures that all the constituent characters witll be spit out. Here is the script :

```python
from pwn import *
from tqdm import tqdm

io = remote('challs.actf.co', 32100)

def query(io, to_send):
    io.recvuntil(b':')
    io.sendline(b'1')
    io.recvuntil(b'>')
    io.sendline(to_send)
    m = int(io.recvline().strip())
    return m


so_far = set()
for _ in tqdm(range(100)):
    try:
        r = query(io, '0'.encode())
        so_far.add(r)
    except:
        io = remote('challs.actf.co', 32100)

print(so_far)
```
The ouput was ```{'8', 'b', 't', '}', '7', '{', 'f', 'c', '6', 'a', '0'}```

Not much, just 11 unique characters. Using them, I tried to write a partial burte force using ```z3```. Since I can have 10 equations, I bruteforced for the 8 remaining characters. Later I tried a similar approach using matrices. Brute-forcing for the 8 remaining characters, I formed a ```10 by 10``` matrix and solving it under GF(M). But both the approaches were too slow and hence, not feasible.


## The working approach

Notice that I can somewhat reduce the search space  using ```query1('x')``` and ```query1('-x')``` where `x` is an integer. 
$$f(x)  = a_0 + a_1x + a_2x^2 + a_3x^3 + a_4x^4 + ... + a_{16}x^{16} + a_{17}x^{17} $$
$$f(-x) = a_0 - a_1x + a_2x^2 - a_3x^3 + a_4x^4 + ... + a_{16}x^{16} - a_{17}x^{17} $$

Adding them cancels out the indices with odd powers:

$$f(x) + f(-x) = 2a_0 + 2a_2x^2 + 2a_4x^4 + 2a_6x^6 + ... + 2a_{14}x^{14} + 2a_{16}x^{16}$$

Allthough we can't directly query for ```query1('-x')```, we can do ```M - x``` instead, since 
$$M \ - \ x \ \equiv \ -x \ mod \ M$$

But how does this help us? Not that we can brute force all combinations, it's $O(n^9)$ which is too costly.
Instead, we can divide it into two parts, 
$$g_1(x) \ = \ a_0 + a_2x^2 + a_4x^4 + a_6x^6 + a_8x^8$$ 
$$g_2(x) \ = \ a_{10}x^{10} + a_{12}x^{12} + a_{14}x^{14} + a_{16}x^{16} $$

We now brute force all combinations of ```g1(p)``` where the ```p``` is fixed(supposedly a prime) and ($a_0, a_2, a_4, a_6, a_8$) are chosen from the flag characters which we got initially. The values are stored in a dictionary where ```g1(p)``` is the key and the combination of co-efficients is the value.

```python
import itertools

opt = ['8', 'b', 't', '}', '7', '{', 'f', 'c', '6', 'a', '0']
opts = [ord(c) for c in opt]
perms5 = list(itertools.product(opts, repeat = 5)) # all permuations and combinatons of length 5
perms4 = list(itertools.product(opts, repeat = 5)) # all permuations and combinatons of length 4, will be used later

M = (1 << 127) - 1
d1 = dict()
p1 = 23
for perm in tqdm(perms5):
    pwL = [0, 2, 4, 6, 8]
    sm = sum([perm[i] * (p1 ** pwL[i]) for i in range(5)])
    d1[sm] = perm
```

The complexity for this part is $O(n^5)$ which is affordable.

Let's say 
$$z \ = \ g_1(p) \ + \ g_2(p)$$
Since we have all permutations for $g_1$, we can write the above equation as 
$$g_1(p) \ = \ z \ - \ g_2(p)$$

Now we brute force all permutations and combinations of length 4 and find different values of $g_2(p)$ <br>
For each value of $g_2(p)$, we check if $z \ - \ g_2(p)$ is in dictionary ```d1```. If yes, we have found the proper combinations of coefficients for $a_0, a_2, a_4, ...., a_{14}, a_{16}$ <br>

```python
RHS = [r1, r2] # r1 = query1(p) r2 = query1(M - p)

p1_sm = (RHS[0] + RHS[1]) % M
p1_sm = (pow(2, -1, M) * p1_sm) % M
even_pow = None
for perm in tqdm(perms4):
    pwR = [10, 12, 14, 16]
    sm = sum([perm[i] * (p1 ** pwR[i]) for i in range(4)])
    need = (p1_sm - sm + M) % M
    if need in d1:
        even_pow = d1[need] + perm
        break
```

How much time does it take? The brute forcing take $O(n^4)$ and the search to see if a value belongs in the dictionary takes $O(\log{} n)$. 
In total it is $O(n^4 \log{} n)$ which is way faster than $O(n^9)$

The exact same approach is repeated to recover the odd indexed coefficients
$$a_{1}x + a_{3}x^3 + a_{5}x^5 + a_{7}x^7 + ... + a_{15}x^{15} + a_{17}x^{17}$$ 

After all the coefficients are recovered, we send them to ```query2``` in order to get the permutations revealed. <br>
Using that, we can rearrange the coefficients and hence, recover the flag.

```python
flag = [0 for _ in range(len(coeffs))]
for idx, val in enumerate(perms):
    flag[val] = coeffs[idx]

flag = ''.join([chr(c) for c in flag])
print(flag)
```

Flag: **actf{f80f6086a77b}**

