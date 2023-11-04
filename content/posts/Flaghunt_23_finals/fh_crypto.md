---
weight: 1
title: "FlagHunt 2023 finals - My Crypto Writeup"
date: 2023-11-04T22:12:00+06:00
lastmod: 2023-11-04T22:20:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for the cryptography problems that I designed."

tags: ["crypto", "FlagHunt", "XOR", "dfs", "meet-in-the-middle", "english"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---

Writeup for the cryptography problems that I designed.

<!--more-->

## Overview
Both of my challenges were made quite challenging for a few reasons
* The feeling of solving a difficult challenge is quite exhilarating
* Teams have little to no motivation for sharing flags which they solve with much hardship

Nevertheless, I hope they proved to be very educational for the pariticpants.

## XOR-Mania

{{< admonition note "Challenge Information" >}}
* **Points:** 200

{{< /admonition >}}

The solution to this problem lies in a very subtle observation that is very likely to be missed. In our given script

```python
from random import randint
import hashlib
from string import ascii_letters, digits

opts = ascii_letters + digits + '!@#$%&_-+=<>.,?;:[]'

# def get_flag(sz):
#     core = ''.join(opts[randint(0, len(opts) - 1)] for i in range(sz))
#     flag = 'CTF_BD{' + core + '}'
#     with open('flag.txt', 'w') as f:
#         f.write(flag)
# #This function was used to produce the flag
# get_flag(30)

flag = open('flag.txt', 'rb').read()
xored = []

for itr in range(650):
    xor = []
    for c in flag:
        c ^= randint(1, 127)
        xor.append(c)
    xored.append(bytes(xor))

hash = hashlib.sha256(flag).hexdigest()
with open('out.txt', 'w') as f:
    for xor in xored:
        f.write(xor.hex() + '\n')
    f.write(hash)
```

Look at this particular line:

```python
c ^= randint(1, 127)
```

Each character `a` of the flag is xored with a random number between `[1, 127]`. What difference would it make if the range was `[0, 127]` instead? 

If the lower bound was 0, there was a chance that that `a` would be xored with 0 and the resulting character would be `a` itself, since xoring with 0 returns the value. But since this is not the case, we will never find a itself there. 

Notice that the xored array is a 2d array, where each element represents the distorted or xored flag. Each character of the flag being xored with a random integer. We can represent it as a matrix:

$$
A_{m,n} = 
\begin{bmatrix}
c_{1,1} & c_{1,2} & \cdots & c_{1,n} \\\
c_{2,1} & c_{2,2} & \cdots & c_{2,n} \\\
\vdots  & \vdots  & \ddots & \vdots  \\\
c_{m,1} & c_{m,2} & \cdots & c_{m,n} 
\end{bmatrix}
$$

What would a particular column in this matrix mean?

$$
A_{k} = 
\begin{pmatrix}
c_{1,k} \\\
c_{2,k} \\\
\vdots  \\\
c_{m,k}
\end{pmatrix}
= \begin{pmatrix}
a_{1,k} \oplus r_{1, k} \\\
c_{2,k} \oplus r_{2, k} \\\
\vdots  \\\
c_{m,k} \oplus r_{m, k}
\end{pmatrix}
$$


This column represents all the xors for a character at position `k`. `r` represents the random integer the character is xored with.  If the character of the flag at `k-th` position was $a_k$ , it is guaranteed that $A_k$ will never contain $a_k$ because of the reason explained above. 

Since there are around 750 elements in this column, almost all the numbers from `[1, 127]` will come in through random generation and xor the $c_k$ . Now through elimination, we can check that which character in range `[0, 127]` does not belong in that column. That is the value of $c_k$ . 

But in reality, there would still be some positions where there won't be only one value remaining. The probability that a number `a` won't be drawn even once in a column of 650 elements is around

$$ 
\begin{equation}
(\frac{126}{127})^{650} \ * \ 100 \ \\% \approx 0.58 \ \\% 
\end{equation}
$$

Even if this value is very small, it is not completely negligible. Maybe some positions will have 2 to 3 remaining characters to be eliminated. That is why the flag hash was given. The problem was designed as such there are around 20 positions at max where the original character can not be uniquely determined. A  `dfs` can be written that checks all possible combinations for the remaining characters and match which one gives the actual hash. There are at max around $3^{20}$ (which is still a very big upper bound, the actual value is much lesser) leaf nodes in the dfs. This is feasible and would take only a couple of minutes in any modern pc to run. 

```python
import hashlib
import copy

info = open('out.txt', 'r').read().split('\n')
xored, hash = info[:-1], info[-1]

xored = [bytes.fromhex(xor) for xor in xored]
flag_len = len(xored[0])
opts = set(c for c in range(128))

possible_pos = dict()
problematic = []
ans = []

for pos in range(flag_len):
    found = set()
    for itr in range(len(xored)):
        found.add(xored[itr][pos])
    remaining = opts.difference(found)
    sz = len(remaining)
    if sz == 1:
        ans.append(list(remaining)[0])
    else:
        ans.append(0)
        problematic.append(pos)
        possible_pos[pos] = list(remaining)

print(problematic)
print(possible_pos)

def dfs(idx, cur_arr):
    if idx == len(problematic):
        H = hashlib.sha256(bytes(cur_arr)).hexdigest()
        if hash == H:
            print(bytes(cur_arr))
            exit(2)
        return
    else:
        for pos in possible_pos[problematic[idx]]:
            nw_arr = copy.deepcopy(cur_arr)
            nw_arr[problematic[idx]] = pos
            dfs(idx + 1, nw_arr)

dfs(0, ans)
```

{{< admonition tip "Fun Fact" >}}
The flag characters were made random so that you couldn't guess any of the characters by luck, rather you were bound to apply backtracking!

{{< /admonition >}}

> Flag : **CTF_BD{u,Q6U6p97gJcV%QUVgn0hckLEW\[=u-}**


## Primes Festival

{{< admonition note "Challenge Information" >}}
* **Points:** 300

{{< /admonition >}}


This is a very classic problem. Meet in the middle attack on subset products is the main theme here. 

```py
#!/usr/local/bin/python

from Crypto.Util.number import getPrime, isPrime
from Crypto.Random.random import getrandbits

print('Welcome to yet another guess my favorite number chall!!!')

st = 1 << 20
primes = []

while len(primes) != 47:
  if isPrime(st):
    primes.append(st)
  st += 1

def ok(x):
  on = bin(x)[2:].count('1')
  return on >= 36

while True:
  secret = getrandbits(46)
  if ok(secret):
    break

hint = 1
for i in range(46):
  if (secret >> i) & 1:
    hint *= primes[i]

p = getPrime(512)
hint %= p

print('I will be generous to give you a hint :', hint, p)
  
num = int(input('Enter my favorite number: '))
if num == secret:
  print(open('flag.txt', 'r').read())
else:
  print("Nope, it's wrong!!")
```

Let us try to understand the problem setting. We have a pool of 47 primes numbers(which we know). Of them, some primes are selected at random(the number of primes selected can vary from 36 to 46) and they are multiplied and reduced via a huge prime. This reduced number is the given hint. 

But how does this correlate with the secret number that we have to guess? The secret number is a 46 bit number that can have the set bits(bits that are 1) with count from 36 to 46. The indices of the set bits are what we use as the prime indices for our product.

That is, from a set of primes,


$$P = [p_1, p_2, p_3,\ \cdot \cdot \cdot \ , p_{47}] $$

We need to find a subset `S`, where,

$$ S = [s_1, s_2, s_3, \ \cdot \cdot \cdot \ , s_k] $$

Such that, 

$$ hint = p_{s_1} * p_{s_2} * p_{s_3} \ \cdot \cdot \cdot \ * p_{s_K} $$

Cult classic subset product problem. There are tons of algorithms to solve this problem. The one we are going to use here is the `meet-in-the-middle algorithm`.

Now, the most naive algorithm would have been to enumerate over all possible subsets possible and check if the product matches with the given hint. But the problem with this approach is that the time complexity is too high. There are 47 elements, and thus the total number of possible subsets is $2^{47}$. The number of operations are too big and hence not feasible. We have to reduce this complexity somehow.  

This is where `meet-in-the-middle` comes in. We will divide the set of primes into two different sets as follows:

$$ P_1 = [p_1, p_2, p_3, \ \cdot \cdot \cdot \ , p_{23}] $$

$$ P_2 = [p_{24}, p_{25}, p_{26}, \ \cdot \cdot \cdot \ , p_{47}] $$

We can write the hint as,

$$ hint = prod_1 * prod_2 \mod P $$

For any integers $prod_1$ and $prod_2$ which are also some subset products from the prime set. Instead of trying to find $prod_1$ and $prod_2$ individually, we would re-write this equation a bit:

$$ prod_1 = hint * prod_2 ^ {-1} \mod P $$

For each $prod_2$, we check if there is a valid $prod_1$. How? Let's see in detail below:

We will now do the subset enumeration on the set $P_1$ first. This is feasible since there are $2^{23}$ subsets only. Let's say, we have a map $M$.  For each subset, we store the product as the key and the bitmask as the value in this map. We store all combinations of $prod_1$ in $M$. 

Then we do this exact same type of enumeration on the second set $P_2$ as well. But, for a bitmask $b$, let's say we got a product $prod_2$. What value would we require to multiply with it to produce $hint$ ? 

$$prod_2 * x = hint \mod P$$

$$=> x = hint * prod_2 ^ {-1} \mod P$$

This $x$ here is the $prod_1$ we calculated in our map $M$. So, we check if there is the $x$ in that map. If there is, we have found our required bits to make $hint$. Else, we just keep on enumerating until all the bits are found. 

$$secret = (mask_2 << 23) \ | \ mask_1 $$

This has a complexity of `O(nlog(n)`. Where $n=2^{23}$.

```python
from pwn import *
from tqdm import tqdm
from Crypto.Util.number import isPrime

st = 1 << 20
primes = []
while len(primes) != 47:
  if isPrime(st):
    primes.append(st)
  st += 1
  
p1 = primes[:23]
p2 = primes[23:]

io = remote('127.0.0.1', 5000)
io.recvline()
io.recvuntil(b': ')

hint, p = map(int, io.recvline().decode().strip().split(' '))

vals1 = dict()
for mask in tqdm(range(1 << 23)):
  prod = 1
  for i in range(23):
    if (mask >> i) & 1:
      prod = (prod * p1[i]) % p
  vals1[prod] = mask

for mask in tqdm(range(1 << 23)):
  prod = 1
  for i in range(23):
    if (mask >> i) & 1:
      prod = (prod * p2[i]) % p
  need = (hint * pow(prod, -1, p)) % p

  if need in vals1:
    bits = vals1[need]
    ans = (mask << 23) + bits
    print('Secret num:', ans)
    break

io.recvuntil(b': ')
io.sendline(str(ans).encode())
io.interactive()
```

> Flag : **CTF_BD{Numb34_7h30ry_4nD_M33t_1n_7h3_M1ddl3_15_4_v34y_b3au71ful_c0mb1n4710n!!}**

