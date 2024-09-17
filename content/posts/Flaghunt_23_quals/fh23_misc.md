---
weight: 1
title: "FlagHunt 2023 quals - My Misc Writeup"
date: 2023-10-08T17:26:00+06:00
lastmod: 2023-10-08T17:26:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for the misc problems that I designed."

tags: ["misc", "FlagHunt", "algorithms", "english"]
categories: ["Writeups"]

lightgallery: true

---

Writeup for the misc problems that I designed.

<!--more-->

## Overview

Wanted to give a very trivial algorithmic challenge, that must be scripted. 

## Palindrome

{{< admonition note "Challenge Information" >}}
* **Points:** 150

`nc 45.76.177.238 5000`

{{< /admonition >}}


When we connect to the server, we are greeted with a message that says we will be given a string and we have to find out what is the minimum number of characters that must be changed to make it a palindrome. This must be done a thousand times to get the flag. 

The main challenge here is to figure out the minimum changes required to make a string palindrome. How do we define palindromes? A `palindrome` is a string that reads the same from the front and the back. That is, if we have a string `S`

$$S = c_1 \ c_2  \ c_3 \ \cdots \ c_{n - 2} \ c_{n - 1} \ c_{n} $$ And let the reverse of the string be $S_r$ 

$$S_r = c_{n} \ c_{n - 1}  \ c_{n - 2} \ \cdots \ c_{3} \ c_{2} \ c_{1}$$

The string `S` will be a palindrome if and only if $S = S_{r}$ . That is, 

$$ c_1 = c_{n}$$

$$c_2 = c_{n - 1}$$

$$c_3 = c_{n - 2}$$

$$ \vdots$$

So, for a string `S`, the `i-th` character must be changed if and only if,

$$c_i \neq c_{n - i + 1}$$

We just find how many such inequalities are there and divide that count by 2. But why the division by 2? That is to subtract overcounting. Let us take an example to understand it better:

$$S = abcdp$$

$$S_r = pdcba$$

There are 4 unequal pairs here : `(a, p), (b, d), (d, b), (p, a)`.
Notice that we are counting both the first and the last `(a, p)` mismatch. Had we changed `a` to `p`, the pair `(p, a)` would have been resolved as well. Same goes for `(b, d)`. That is why we divide the inequality count by 2. 

```python
from pwn import *

io = remote('45.76.177.238', 5000)

for _ in range(4):
    io.recvline()

for _ in range(1000):
    s = io.recvline().decode().strip().split(': ')[1].replace(' ', '')
    ans = sum([a == b for a, b in zip(s, s[::-1])]) // 2
    io.sendline(str(ans).encode())
    io.recvline()
    
io.interactive()
```

> Flag : **CTF_BD{palindrome_checking_is_a_very_simple_concept_something_that_even_a_CS_fresher_can_code_himself_at_ease:3}**

