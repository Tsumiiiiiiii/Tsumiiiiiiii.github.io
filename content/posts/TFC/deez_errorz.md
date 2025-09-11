---
weight: 1
title: "TFC CTF 25 - Writeup for Deez Errorz crypto challenge"
date: 2025-09-09T17:30:00+06:00
lastmod: 2024-09-09T17:30:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Solving an instance of the LWE problem with errors sourced from a known trinomial distribution"

tags: ["crypto", "TFC", "LWE", "LLL", "primal attack", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true

---

<!--more-->

Let's begin with analysing the given script, which is short and compact

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
import random
from secret import flag

mod = 0x225fd
flag = bytes_to_long(flag)
e_values = [97491, 14061, 55776]
S = (lambda f=[flag], sk=[]: ([sk.append(f[0] % mod) or f.__setitem__(0, f[0] // mod) for _ in iter(lambda: f[0], 0)],sk)[1])()
S = vector(GF(mod), S)

A_save = []
b_save = []

for i in range(52):
    A = VectorSpace(GF(mod), 44).random_element()
    e = random.choice(e_values)
    b = A * S + e
    #print(b)

    A_save.append(A)
    b_save.append(b)

open('out.txt', 'w').write('A_values = ' + str(A_save) + ' ; b_values = ' + str(b_save))
```

The entire process consists of some elementary matrix operations that can be represented as $b_i = \langle A_i, S \rangle + \ e_i$.

$$
\begin{bmatrix}
b_0 \\\
b_1 \\\
\vdots \\\ 
b_{51}
\end{bmatrix}
= \\
\begin{bmatrix}
A_{0,0} & A_{0,1} & \dots & A_{0,43} \\\
A_{1,0} & A_{1,1} & \dots & A_{1,43} \\\
\vdots  & \vdots  & \ddots & \vdots \\\
A_{51,0} & A_{51,1} & \dots & A_{51,43}
\end{bmatrix}
\begin{bmatrix}
S_0 \\\
S_1 \\\
\vdots \\\
S_{43}
\end{bmatrix}
+
\begin{bmatrix}
e_0 \\\
e_1 \\\
\vdots \\\
e_{51}
\end{bmatrix}
$$


This is the well known LWE(learning with error) setup where the $b$ vector and $A$ matrix is known, whereas the secret $S$ vector and the error vector $e$ is unknown. Our goal is to recover $S$. However, we do know a crucial information about the error terms - they come from a trinomial distribution. In fact, the pool is known, and $e_i \in \\{97491, 14061, 55776\\}$.

We have to take advantage of this very short distribution somehow, as it seems like the weakest point in the link. Because, if we can shorten the error terms further, we can apply some well known lattice reduction attack on it somehow. Maybe we can replace the errors with some other variable terms?

## An equation in 3 unknowns - The baby step

$e_i = t_0 * 97491 + t_1 * 14061 + t_2 * 55776$ where $t_i \in \\{0,1\\}$


| e    | $t_0$ | $t_1$ | $t_2$|
|---   |-----|-----|----|
| 97491| 1   | 0   | 0  |
| 14061| 0   | 1   | 0  |
| 55776| 0   | 0   | 1  |

We are encoding the error using 3 bits, but can we reduce the number of bits here?

## Towards a bivariate equation

Turns out, we can - using something called the linearization technique.

$e_i = 97491 + t_0*(14061 - 97491) + t_1*(55776 - 97491)$

| e    | $t_0$ | $t_1$ |
|---   |-----|-----|
| 97491| 0   | 0   |
| 14061| 0   | 1   |
| 55776| 1   | 0   |

We are essentialy representing the same equation, but using 2 bits instead of 3.

## Shortening it even further

As it turns out, due to how the error distribution is chosen, we can convert it to a monovariate equation. Consider the bivariate equation from last step, but with the constants permuted: $e_i = 55776 + t_0*(55776 - 97491) + t_1*(55776 - 14061)$. Taking the equation one step further gives 

$$
\begin{aligned}
e_i &= 55776 + t_0 * (-41715) + t_1*(41715) \\\
&= 55776 + 41715*(t_1 - t_0) \\\
&= 55776 + 41715 * t
\end{aligned}
$$

where $t \in \\{-1, 0, 1\\}$

This lets us write $b_i = \langle A_i, S \rangle + 55776 + 41715 * t_i$. Rearrenging a bit, we have $\frac{b_i - 55776}{41715} = \frac{\langle A_i, S \rangle}{41715} + t_i$. Or simply write it as $b'_i = \langle A'_i, S \rangle + t_i$, where the $b'_i$ and $A'_i$ can be calculated. We now have an error vector which is extremely small $\in \\{-1, 0, 1\\}$. 

## The finishing touch

This is a well studied problem now, thanks to the shortened error pool. We can mount a primal attack using lattices that yields us the errors.The following basis does the job for us,

$$
\begin{bmatrix}
A_{0,0} & A_{0,1} & \dots & A_{0,43} & b_0 & q & 0 & \dots & 0 \\\
A_{1,0} & A_{1,1} & \dots & A_{1,43} & b_1 & 0 & q & \dots & 0 \\\
\vdots  & \vdots  & \ddots & \vdots  & \vdots & \vdots & \vdots & \ddots \\\
A_{51,0} & A_{51,1} & \dots & A_{51,43} & b_{51} & 0 & 0 & \dots & q
\end{bmatrix}
$$

The error is extremely short and is guaranteed to be in the reduced basis

$$
s_0 
\begin{bmatrix}
A_{0,0} \\\ A_{1,0} \\\ \vdots \\\ A_{51,0}
\end{bmatrix}
+s_1 
\begin{bmatrix}
A_{0,1} \\\ A_{1,1} \\\ \vdots \\\ A_{51,1}
\end{bmatrix}
+\cdots + s_{43} 
\begin{bmatrix}
A_{0,43} \\\ A_{1,43} \\\ \vdots \\\ A_{51,43}
\end{bmatrix}
-1
\begin{bmatrix}
b_{0} \\\ b_{1} \\\ \vdots \\\ b_{51}
\end{bmatrix}
+k_1
\begin{bmatrix}
q \\\ 0 \\\ \vdots \\\ 0
\end{bmatrix}
+k_2
\begin{bmatrix}
0 \\\ q \\\ \vdots \\\ 0
\end{bmatrix}
+\cdots + k_{51}
\begin{bmatrix}
0 \\\ 0 \\\ \vdots \\\ q
\end{bmatrix}
= \\
\begin{bmatrix}
t_0 \\\ t_1 \\\ \vdots \\\ t_{51}
\end{bmatrix}
$$


```python
A_ = []
b_ = []
q = mod
m = 52
for i, row in enumerate(A):
    inv = pow(41715, -1, q)
    row_ = [(i * inv) % q for i in row]
    A_.append(row_)
    b_.append((b[i] * inv) % q)

A_ = matrix(F, A_)
M = (
    A_.change_ring(ZZ)
    .augment(vector([i for i in b_]))
    .augment(diagonal_matrix([q]*m))
    .T
)

M_ = M.BKZ(block_size = 15)
print('BKZ done')
for row in M_:
    if len(set(row)) == 3:
        print('eh??')
        errors = [e3 + 41715*bit for bit in row] # or it could be e3 - 41715*bit; in my case taking (+) gave a determined system of equations
        print(errors)
        break
```

Once the secret is leaked, this reduces to the problem of solving a properly determined system of equations(43 equations in 43 unknowns)

```python
rem = vector(F, b_values) - vector(F, errors)
sec = A.solve_right(rem)
print(sec)
```
