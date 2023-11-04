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
* Teams have little to no motivation for sharing flags which they solve with much hardship* 

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
\begin{equation}
A_{k} = 
\begin{pmatrix}
c_{1,k} \\\
c_{2,k} \\\
\vdots \\\
c_{m,k}  
\end{pmatrix}
 = \begin{pmatrix}
a_{1,k} \oplus r_{1, k} \\\
a_{2,k} \oplus r_{2, k} \\\
\vdots \\\
a_{m,k} \oplus r_{m, k}  
\end{pmatrix}
\end{equation}
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

> Flag : **CTF_BD{u,Q6U6p97gJcV%QUVgn0hckLEW\[=u-} **
