---
weight: 1
title: "AmaterusCTF 2023 - lce cream generator Writeup"
date: 2023-07-20T15:02:00+06:00
lastmod: 2023-07-20T15:02:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for the Ice cream generator Cryptography challenge."

tags: ["crypto", "amateurs CTF", "LCG", "english"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---

Writeup for the Ice cream generator Cryptography challenge.

<!--more-->

## Overview

This was the first edition of Amateurs CTF and I absolutely loved the challenges. Managed to solve 7/12 crypto challenges. They were really fun and educational. 
But `Ice cream generator` was the most beautiful of them all (also my favorite problem of this year so far) 😍. I plan to make a detailed writeup of it.

## The challenge

{{< admonition note "Challenge Information" >}}
* **Points:** 495
* **Description:** Ice cream. Or wait... Ice cream. Same difference.

`nc amt.rs 31310`

[main.py](https://amateurs-prod.storage.googleapis.com/uploads/fe298c6cc6b64777761d3f0c97a0b5139569e126f5c4660fa16e796376e83509/main.py)

{{< /admonition >}}

At first glance, this seems to be a huge code with over 200 lines 😨. I immediately dropped the problem, thinking it was overcomplicated for my level, and also because it only had like 2 solves at that moment.
I returned to this problem almost a day later, when someone on the discord mentioned that this was much simpler than it looks.

At its core, this is a very simple `LCG` problem. I would explain what it is, in a short while. What makes this problem special is how we have to crack the generator without having access to the 
generated random numbers(unlike other easy `LCG` problems, where we can just spam some template).

## What is LCG?

`LCG` or [`Linear Congruential Generator`](https://en.wikipedia.org/wiki/Linear_congruential_generator) is an algorithm to generate `Pseudo Random Numbers` using linear equations.
The underlying algorithm is very simple to understand. We can represent it using a recurrence relation like this,
$$X_{n+1} \ = \ aX_n + c \mod\ m$$ 

$X_0$ is the seed, used to generate the other random numbers $X_1, X_2, ..., X_n$

$a$ is the multiplier

$c$ is the increment

$m$ is the modulus

Note that all values are bounded by the modulus $m$.

A simple python implementation of LCG follows

```python
class LCG:
    def __init__(self, a, b, p, seed):
        self.a, self.b, self.p, self.seed = a, b, p, seed

    def gen_next(self):
        self.seed = (self.a*self.seed + self.b) % self.p
        return self.seed
```

## How to crack LCG?

There can be different variations to the problems related to cracking `LCG`. Some give extra information, some go on to even truncate bits from the random numbers to hide information.

The most common variant is to give some generated numbers (usually 6 numbers is enough to recover all the parameters), and one has to find the `a, c, m, seed` from those values. A very beautiful writeup explaining it in detail goes [here](https://flocto.github.io/writeups/2023/deadsecctf/lcg-writeup/). 

In our current problem, `m` and `seed` is already given, making it much easier to solve. We have to recover `a` and `b`.

Let's say we have 3 generated numbers $X_1, X_2, X_3$. 
$$X_2 \ = \ aX_1 + c\mod\ m$$
$$X_3 \ = \ aX_2 + c\mod\ m$$

Subtracting the first equation from the second gives us,
$$X_3 - X_2 \ = \ a(X_2 - X_1) \mod\ m$$
$$a \equiv\ \frac{X_3 - X_2}{X_2 - X_1} \mod\ m$$

So easy to recover `a` 😆. It's trivial to recover `c` now.
$$X_2 \ = \ aX_1 + c\mod\ m$$
$$c \equiv\ X_2 - aX_1 \mod\ m$$

## Let's dive into the given code
