---
weight: 1
title: "Deadsec CTF 25 - Writeup for my EBG crypto challenge"
date: 2025-07-28T17:30:00+06:00
lastmod: 2024-07-28T17:30:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Elliptic curve shenanigans, followed by some sagemath magic, some meet in the middle and some bits of the Hidden Number problem"

tags: ["crypto", "DEADSEC", "elliptic curve", "LLL", "HNP", "MITM", "groebner basis", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true

---

<!--more-->

DeadSec CTF ended a few hours back, and I think as a team we are quite happy with how we managed to pull if off, from creating a set of exciting and engaging challenges, to providing support to the players in the discord, and not to mention the smooth infrastructure(thanks to @Buckley for that).

As for me, I wrote 3 problems this time around, all being in the crypto category. The harder one, called EBG is definitely the hardest challenge I have written so far and fortunately many players deemed it educational, which in fact was my goal. This particular writeup will hence be a detailed analysis of this particular challenge.

The problem deals with elliptic curves, LCGs, and a few other elements that are somewhat common as far as CTFs are concerned. To begin with, this is the relevant source

```python
#!/usr/bin/env sage

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
from random import randint
from secret import a, b, p, q, flag

Fp = GF(p)
Fq = GF(q)
E = EllipticCurve(Fp, [a, b])

assert a < p and b < p

class LCG:
    def __init__(self, seed, a, b):
        self.a, self.b = Fq(a), Fq(b)
        self.state = Fq(seed)

    def next_state(self):
        nxt = self.state * self.a + self.b
        self.state = nxt
        return int(nxt)

seed = randint(1, q)
lcg = LCG(seed, a, b)

collect, points = [], []

itr = 0
while len(collect) != 50:
    itr += 1
    y = lcg.next_state()
    P.<x> = PolynomialRing(Fp)
    try:
        x_ = (x^3+a*x+b-y^2).roots()[0][0]
        assert (x_, y) in E
        collect.append((itr, x_, Fp(y^2)))
        points.append((x_, Fp(y)))
    except:
        pass

qsz = q.bit_length()
qhi = q >> (qsz//2)
qlo = q & ((1 << (qsz//2)) - 1)

assert qhi.bit_length() == qsz//2 == 84
assert qlo.bit_length() == qsz//2

G = E.gens()[0]
hints = [
    sum([i[1]*G for i in points]).xy(),
    ((qhi^2 + (qlo^3)*69) * G).xy(),
    (((qhi^3)*420 + qlo^2) * G).xy()
]

for _ in range(10^18):
    lcg.next_state()

key = sha256(str(lcg.next_state()).encode()).digest()
ct = AES.new(key, AES.MODE_ECB).encrypt(pad(flag.encode(), 16)).hex()

with open('output.txt', 'w') as f:
    f.write(f'{collect=}\n')
    f.write(f'{hints=}\n')
    f.write(f'{ct=}')
```

The setting behind the challenge is that we have an elliptic curve with unknown paramters, along with an LCG, whose paramters are unknown as well. 

The outputs of the LCG are used as the `y` co-ordinate of the elliptic curve, and we are given the $(x, y^2)$ points. Then we are given some "hints", namely the summation of the $y$ co-ordinates, multiplied with the generator($G$) of the elliptic curve. Lastly, we have two polynomials made from the lower and higher bits of the LCG modulus($q$) multiplied with the same $G$.

Roughly speaking, this problem can be divided into 5 different challenges that are fairly independent of one another-

1. Recovering the Elliptic Curve paramters($a,b, p$)
2. Recovering the LCG modulus($q$)
3. Correctly distinguising the LCG states.
4. Finding the LCG seed.
5. Calcluating the $10^{18}$-th state of the LCG.

## part 1: Recovering the Elliptic Curve

This writeup assumes you have a basic familiarity with elliptic curves, at the very least you understand what a Weierstrass curve is. In case you don't, [now might be the right time to tame this beast](https://ctf-wiki.mahaloz.re/crypto/asymmetric/discrete-log/ecc/). 

Namely, the Weierstrass form of Elliptic Curve over $GF(p)$ is defined as $y^2 = x^3 + a\cdot x + b$. Nothing complicated, a simple polynomial defined over $x,y$ and calculations defined under modulo $p$. We don't know $a, b$ neither do we know $p$. Instead, we know a set of points given as hint. Particularly, we have $(x, y^2)$ which will come in handy to recover the unknowns. By the way, $y$ squared is actually reduced modulo $p$, in case you were thinking of infering the LCG states directly :anguished: 

{{< admonition type=tip title="Some notes" open=true >}} Weierstrass curve in fact is vastly difficult from what I have explained above. But the simpler variant does more than well to do the job here, hence the simplification. {{< /admonition >}}

Let us jot down what we have and work from there:

$$
\begin{aligned}
y_1^2 \equiv x_1^3 + ax_1 + b \mod p \\\
y_2^2 \equiv x_2^3 + ax_2 + b \mod p\\\
y_3^2 \equiv x_3^3 + ax_3 + b \mod p\\\
\vdots \\\
y_n^2 \equiv x_n^3 + ax_n + b \mod p
\end{aligned}
$$

A simple algebraic manipulation shows:

$$
a \equiv \frac{(y_1^2 - y_2^2) - (x_1^3 - x_2^3)}{x_1 - x_2} \equiv \frac{(y_2^2 - y_3^2) - (x_2^3 - x_3^3)}{x_2 - x_3} \equiv \cdots \equiv \frac{(y_{i}^2 - y_{i+1}^2) - (x_i^3 - x_{i+1}^3)}{x_i - x_{i+1}} \mod p
$$

Taking the first relation, 

$$
\begin{aligned}
((y_1^2 - y_2^2) - (x_1^3 - x_2^3)) (x_2 - x3) 
& \equiv ((y_2^2 - y_3^2) - (x_2^3 - x_3^3)) (x_1 - x_2) &&\mod p \\\
((y_1^2 - y_2^2) - (x_1^3 - x_2^3)) (x_2 - x3) - ((y_2^2 - y_3^2) - (x_2^3 - x_3^3)) (x_1 - x_2) & \equiv 0 &&\mod p \\\
((y_1^2 - y_2^2) - (x_1^3 - x_2^3)) (x_2 - x3) - ((y_2^2 - y_3^2) - (x_2^3 - x_3^3)) (x_1 - x_2) & =  k_1p 
\end{aligned}
$$

Notice that the left hand side of this equation can be calculated fully as we have all the values to do so, and this value happens to be a multiple of the unknow $p$. In a similar fashion, we can take a bunch of more relations to get a few more multiples of $p$. Finally taking the GCD of them reveals the Elliptic Curve modulus $p$.

It is trivial to recover $a, b$ once the modulus is found,

$$
\begin{aligned}
a &\equiv \frac{(y_1^2 - y_2^2) - (x_1^3 - x_2^3)}{x_1 - x_2} &&\mod p \\\
b &\equiv y_1^2 - x_1^3 - ax_1 && \mod p
\end{aligned}
$$

The code below does this job precisely.

```python
def recover_params(dirty):
    stuff = [(x,y2) for _, x, y2 in dirty]
    dy2, dx3, dx = [], [], []
    for pt1, pt2 in zip(stuff, stuff[1:]):
        dy2.append(pt2[1] - pt1[1])
        dx3.append(pt2[0]^3 - pt1[0]^3)
        dx.append(pt2[0] - pt1[0])

    diffs = []
    for i in range(20):
        diffs.append((dy2[i] - dx3[i])*dx[i + 1] - (dy2[i+1] - dx3[i+1])*dx[i])
    
    from functools import reduce
    p = reduce(gcd, diffs)
    assert is_prime(p)
    F = GF(p)
    a = F(dy2[0] - dx3[0]) / F(dx[0])
    b = F(stuff[0][1] - stuff[0][0]^3 - a*stuff[0][0])
    return p,a,b

p, a, b = recover_params(collect)
```

## part 2: Recovering the LCG modulus

The 2nd and the 3rd hints will be useful in this particular stage

$$
\begin{aligned}
hint_2 &= (q_{hi}^2 + q_{lo}^3 \cdot 69)  G \\\
hint_3 &= (q_{hi}^3\cdot420 + q_{lo}^2)  G
\end{aligned}
$$

where $G$ is a generator of the elliptic curve we now know of. This is elliptic curve arithmetic and we need to seperate the raw polynomial terms somehow from the elliptic curves. Like every other elliptic curve challenges out there, the first intuition should be to check if the order is smooth. 

A quick check in sage confirms our assumption!

```python
E = EllipticCurve(GF(p), [a, b])
factor(E.order())
# 23 * 16883 * 43093 * 63247 * 12779779 * 14406383 * 1447085987
```

Voila! The order is extremely smooth! And for smooth order groups such as this, the discrete logarithm problem is as easy as a walk in the park. In fact, we can deploy a one liner in sage to carry out the job for us.

```python
v1 = G.discrete_log(E(hints[1]))
v2 = G.discrete_log(E(hints[2]))
```
Where $o$ is the elliptic curve order,

$$
\begin{aligned}
v_1 &= (q_{hi}^2 + q_{lo}^3 \cdot 69) &&\mod o \\\
v_2 &= (q_{hi}^3\cdot420 + q_{lo}^2) &&\mod o
\end{aligned}
$$

That means, right now we have two polynomials in two variables modulo the order. Allthough not impossible, it's far easier to solve a polynomial in one unknown, rather than dealing with two, and this is what we aim to do - convert the two polynomials into one with a single unknown. Time for some sage math shenanigans. Credit goes to [@blupper](https://github.com/TheBlupper) for showing this on the CH discord!

<img width="1045" height="265" alt="image" src="https://github.com/user-attachments/assets/f81930a0-c0f9-4dc6-9fa9-0504bba1ac23" />

We modify the approach shown, and hence comes the following snippet of code that nicely does the job

```python
P.<qhi,qlo, v1, v2> = QQ[]
f1 = qhi^2 + (qlo^3)*69 - v1
f2 = (qhi^3)*420 + qlo^2 - v2
I = ideal([f1, f2])
I.elimination_ideal([qlo]).gens()
#352732968000*qhi^9 - 2519521200*qhi^6*v2 + 5998860*qhi^3*v2^2 + qhi^4 - 2*qhi^2*v1 - 4761*v2^3 + v1^2
```
I dont understand how this works myself, but my guess is that sage uses a mixture of groebner basis and resultants internally to single out and eliminate a  vairable of our choice(in this case the $q_{lo}$).

$$
f = 352732968000\*q_{hi}^9 - 2519521200\*q_{hi}^6\*v_2 + 5998860\*q_{hi}^3*v_2^2 + q_{hi}^4 - 2\*q_{hi}^2\*v_1 - 4761\*v_2^3 + v_1^2 \equiv 0 \mod o
$$

Alright, we have a univariate polynomial in terms of $q_{hi}$, exactly what we were looking for! We can find the roots of this equation easily in sage, and in turn use that to find $q_{lo}$ as well. 

```python
o = E.order()
Zn = Zmod(o)
P.<x> = PolynomialRing(Zn)
f = 352732968000*x^9 - 2519521200*x^6*v2 + 5998860*x^3*v2^2 + x^4 - 2*x^2*v1 - 4761*v2^3 + v1^2
for r1 in f.roots(multiplicities=False):
    for r2 in Zn(v2 - (r1^3)*420).sqrt(all= True):
        r1, r2 = int(r1), int(r2)
        
        q_ = (r1 << r1.bit_length()) + r2
        #note that there can be multiple possible primes, 
        #we can eliminate all to a single solution if we account 
        #for the fact that q_hi and q_lo are qual in temrs of bit length
        if is_prime(q_) and r1.bit_length() == r2.bit_length():
            q = q_
            break

print(q)
```

## part 3: Recovering the LCG states

It's been a long read so far, and in case you have already forgotten, the LCG outputs were used as the y co-ordinates of the curve, and as hints we are given $y^2 \mod p$. We need to recover the $y$'s individually if we are to progress further into the challenge. 

Calculating the square root modulo a prime number is infact an easy problem, thanks to the toneli shanks algorithm. The catch here, however, is that there are two possible square roots: $y$ and $-y \mod p$. It is necessary to distinguish if each of the LCG outputs were $y$ or instead, $-y \mod p$. 

This is where the first hint comes in. If we denote the LCG states as $y$, what first hint gives us is simply,

$$
\begin{aligned}
hint_1 &= y_1G + y_2G + y_3G + \cdots y_{50}G \\\
&= (y_1 + y_2 + y_3 + \cdots + y_{50})G
\end{aligned}
$$

As discussed already in the previous step, taking discrete logs is rather trivial here, and hence, this lets us easily have,

$$
s \equiv y_1 + y_2 + y_3 + \cdots + y_{50} \mod o
$$

For each $y_i$ we have two choices: \[$y_i, -y_i \mod p$\]. That means for the 50 lcg states, we have in total a good $2^{50}$ choices. That is a lot to prune, be it in terms of time or in memory. The experienced players could already guess the tool suitable for this task at hand: `meet-in-the-middle`. 

Now I do not intend on discussing this already well studied trick in detail, you can find plenty of resources online if you dig in a little. In fact, I have written challenges based on this trick myself before. You can see them [here](https://tsumiiiiiiii.github.io/bctd24_quals/#approach-ii--smarter-brute-force-meet-in-the-middle-) and [here](https://tsumiiiiiiii.github.io/fh_crypto/#primes-festival). 

Roughly speaking, we can partition the $y$'s into two sets and prune each of them. Namely, suppose the first 25 states($y_1, y_2, \cdots, y_{25}$) belong in the first set and the last 25 states belong in the other set($y_{26}, \cdots, y_{50}$). In the above equation, we can move the terms of the first set to the LHS,

$$
s - (y_1 + y_2 + \cdots y_{25}) \equiv (y_{26} + y_{27} + \cdots + y_{50}) \mod o
$$

Notice that there can be a total of $2^{25}$ combinations for each side of this equation, a figure reasonable enough to brute force. We can enumerate all of them and calculate the resulting sum, in the process storing the summand and the indices of the states responsible. We can use any data structure of our choice, preferably something that has a fast retrieval. In python the built in dictionary is fast enough, as it supports retrieval in logarithmic complexity. 

Next, we reuse the same logic in the other set, enumerating all possible combinations, and once we calculate a summand, we check if it exists in the previous dictionary. For only the right combination will we hit a match. The first step takes around $2^{25}$ complexity, followed by $2^{25}\log(2^{25})$ for the second step. 


```python
from tqdm import tqdm

mp = {}
#enumerating the first set
for mask in tqdm(range(1<<25)):
    sm = sum([le[i][int(mask >> i) & 1] for i in range(25)])
    mp[sm % o] = mask
    
#enumerating the second set
for mask in tqdm(range(1<<25)):
    sm = sum([ri[i][int(mask >> i) & 1] for i in range(25)])
    need = (tgt - sm) % o
    #check if a match has been found in the dictionary
    if need in mp:
        print('Match found')
        print(mp[need], mask)
        mask1 = mp[need]
        y = [le[i][int(mask1 >> i) & 1] for i in range(25)] + [ri[i][int(mask >> i) & 1] for i in range(25)]
        print(y)
        break
```

Sage predicted that the whole computation would take more than half an hour, thanks to my potato. So I instead opted for good old google colab, where it took roughly 4 minutes to finish. 

## part 4: Recovering the LCG seed (truncated LCG in disguise?)

Alright, now that we do have the original LCG states, and we also know all the LCG params($a, b$ from the elliptic curve is used as the multiplier and adder of the prng respectively), the rest should be fairly straightforward, no? Turns out, this step alone becomes a fairly interesting CTF challenge, thanks to the fact that the bit length of $p$ is smaller than that of $q$.

Notice the LCG calculations are done modulo $q$, but what we are given, however, is $y^2 \mod p$. A quick check in sage reveals that q is in fact 40 bits longer than p.
```python
p.bit_length(), q.bit_length()
#128, 168
```

That means, even though we have managed to recover the actual states mod $p$, we have, in reality, lost 40 bits of information per state. If the actual states were $s_i$, we have $y_i = s_i \mod p$. 

This is a truncated LCG problem, only in other challenges we deal with reduction by a power of two, compared to reduction by a random prime here. The solution however isn't that different at all, in fact we will follow pretty much the same steps that we would have done for the well known case.

Before we proceed any further, it is reccommended that you do know how LCGs work, or how parameter recovery works. You might want to take a look at a previous writeup of mine that deals with [basic LCG parameter recovery](https://tsumiiiiiiii.github.io/lacrypto/#understanding-lcg). 

Alright, we can rewrite the lcg states as, $s_i = y_i + l_i \cdot p$, where $l_i$ is a random integer within the 40 bits range. If we denote the seed as $s_0$, we have,

$$
\begin{rcases}
\begin{aligned}
s_1 &= as_0 + b \\\
s_2 &= a^2s_0 + ab + b \\\
s_3 &= a^3s_0 + a^2b + ab + b \\\
\vdots \\\
s_i &= a^is_0 + (a^{i-1} + a^{i-2} + \cdots + 2 + 1)b
\end{aligned}
\end{rcases}
\mod q
$$


The fact that LCGs can be expressed as a geometric series will be particularly useful in the next phase. Anyway, the LHS of these equations can be written in terms of known $y_i's$,

$$
\begin{rcases}
\begin{aligned}
y_1 + l_1p &= as_0 + b \\\
y_2 + l_2p &= a^2s_0 + ab + b \\\
y_3 + l_3p &= a^3s_0 + a^2b + ab + b \\\
\vdots \\\
y_i + l_ip &= a^is_0 + (a^{i-1} + a^{1-2} + \cdots + 2 + 1)b
\end{aligned}
\end{rcases}
\mod q
$$

Let's change these equations a bit to make them look more friendly

$$
\begin{rcases}
\begin{aligned}
l_1 p &- a s_0 &= T_1 b - y_1 \\\
l_2 p &- a^2 s_0 &= T_2 b - y_2 \\\
l_3 p &- a^3 s_0 &= T_3 b - y_3 \\\
\vdots \\\
l_i p &- a^i s_0 &= T_i b - y_i
\end{aligned}
\end{rcases}
\mod q
$$


Where $T_i = a^{i-1} + a^{i-2} + \cdots + 2 + 1$. Observe that in this set of equations, the unknown terms are $l_1, l_2, \cdots, l_{50}$, each of them being 40 bits, followed by the 168 bit seed, $s_0$. Hmm, they look oddly short, no? Yes you have correctly guessed, this is indeed yet another lattice challenge. 

Honestly speaking, lattices are not at all an easy concept to grasp, but given how extensively they are used throughout cryptography, and also appear in many CTF challenges now a days, it is important to learn them. A resource that I have particularly benefitted from is this [one](https://magicfrank00.github.io/writeups/posts/lll-to-solve-linear-equations/). 

Following the blog linked above, we define a basis:

$$
\begin{pmatrix}
-a   & -a^2   & \cdots & -a^7   & 1 & 0 & 0 & \cdots & 0 \\\
p    & 0      & \cdots & 0      & 0 & 1 & 0 & \cdots & 0 \\\
0    & p      & \cdots & 0      & 0 & 0 & 1 & \cdots & 0 \\\
\vdots & \vdots &      & \vdots & \vdots & \vdots & \vdots & & \vdots \\\
0    & 0      & \cdots & p      & 0 & 0 & 0 & \cdots & 1 \\\
T_1 b - y_1    & T_2 b - y_2      & \cdots & T_7 b - y_7     & 0 & 0 & 0 & \cdots & 0 \\\
q   & 0      & \cdots & 0      & 0 & 0 & 0 & \cdots & 0 \\\
\vdots & \vdots &     & \vdots & \vdots & \vdots & \vdots & & \vdots \\\
0    & 0      & \cdots &    q      & 0 & 0 & 0 & \cdots & 0
\end{pmatrix}
$$

{{< admonition type=tip title="Some notes" open=true >}} As you might have already recognized, this is an instance of the well known  Hidden Number Problem(HNP). {{< /admonition >}}

Thanks to the very small size of the unknowns, we can manage with around 6-7 equations roughly. Although working with 50 equtaions is fine as well. We weigh the columns accordingly before applying LLL

```python
n = 7 
var_names = ['s'] + [f'l{i}' for i in range(n)]
R = PolynomialRing(ZZ, names=var_names)
s, *l = R.gens()

def T(itr):
    ret = 0
    for i in range(itr):
        ret += a^i
    return int(ret % q)

eqs = []
for i, (itr, _, _) in enumerate(collect[:n]):
    lhs = l[i]*p - int(pow(a, itr, q))*s
    rhs = T(itr)*b - ypts[i]
    eqs.append(lhs - rhs)

A,mons = Sequence(eqs).coefficients_monomials(sparse=False)

L = block_matrix(QQ, [
    [A.T,1],
    [q,0]
])

ws = diagonal_matrix([1]*len(eqs) + [1<<168] + [1<<41]*n + [1], sparse=False)
L /= ws
L = L.LLL()
L *= ws
for row in L:
    if row[-1] == 1:
        print(row[n] % q)
        break
```

We are spit out the seed in no time!

## part 5: Forwarding the LCG by $10^{18}$ states

All that is left for us to do is to reocver the AES key, and for that we need the $10^{18}$ th state of the LCG. We can of course iterate linearly and after a while it will finish, even though we will be late by a few light years or so.  

Instead, it is easier to leverage the geometric series property of the LCG. The k-th state can be written as $s_k = a^k + (a^{k-1} + a^{k-2} + \cdots + 2 + 1)b \mod q$. The terms in the coefficient of b follows a pattern that represents a geometric series. Fortunately for us, there exists closed form equations to calculate their value in constant time, namely, $T_k = \frac{a^k - 1}{a - 1}$. Thus, $s_k \equiv a^{k}s + b\frac{a^k - 1}{a-1} \mod q$.

```python
def geo(k, seed, a, b):
    return ((Fq(a)^k) * seed) + Fq(b)*((Fq(a)^k) - 1) / Fq(a - 1)
```

Alright, we have everything that we need to calculate the key and finally recover the flag itself ``^_^``. 

## An unintended solution

As it turns out, the first hint was rather useless, thanks to the fact that we don't need many equations to solve for the seed of the truncated LCG in part 4. We can use, say 7 equations and in the process bruting the sign of those 7 states, and for each of them, apply LLL to find the seed and try to recover the flag. 

What this means is,  we can skip part 3 entirely, and still manage with the rest of the challenge. Thanks to @warri for mentioning this. To be fair, I don't think any of the players used the first hint at all, now that I know of this solve path.Though this does not decrease the challenge difficulty in any way, it's still a fun blupper, or an oversight on my part. This code below is due warri

```python
def sqrt(x):
    global p
    assert p % 8 == 5
    t = pow(x, (p+3)//8, p)
    if (t**2 % p != x % p):
        t *= pow(2, (p-1)//4, p)
        t %= p
    assert t**2 % p == x
    return (t, -t % p)

from math import gcd, lcm
Ts = []
for i in range(0, len(collect[:-2]), 4):
    x0, y0_2 = collect[i][1:]
    x1, y1_2 = collect[i+1][1:]
    x2, y2_2 = collect[i+2][1:]
    x3, y3_2 = collect[i+3][1:]
    r0, r1, r2, r3 = y0_2 - x0**3, y1_2 - x1**3, y2_2 - x2**3, y3_2 - x3**3
    T1 = (r0 - r1) * (x2 - x3)
    T2 = (r2 - r3) * (x0 - x1)
    Ts.append(T1-T2)
p = gcd(*Ts) # 5 mod 8
x0, y0_2 = collect[0][1:]
x1, y1_2 = collect[1][1:]
r0, r1 = y0_2 - x0**3, y1_2 - x1**3
a = (r0 - r1) * pow(x0-x1, -1, p) % p
b = (r0 - a * x0) % p

print(f'{p = }')
print(f'{a = }')
print(f'{b = }')

from sage.all import EllipticCurve, GF, PolynomialRing, crt, Matrix
E = EllipticCurve(GF(p), [a,b])
G = E(211046629312383495603203047061896203904, 184028273928357402268058957910316279756)
H1, H2 = [E(*i) for i in hints[1:]] # hint[0]? whats that?
r1, r2 = H1.log(G), H2.log(G)

GN = G.order()
primes = [i[0] for i in list(GN.factor())]
# [23, 16883, 43093, 63247, 12779779, 14406383, 1447085987]
# skip 23 cuz 69 is present which is a multiple of 23
# skip 1447085987 cuz resultant fails on sage (too big)

xy_mod = lcm(*primes[1:-1])
y_rems = []
for prime in primes[1:-1]:
    FF = PolynomialRing(GF(prime), names=('x, y')); x,y = FF.gens()
    eq0 = y**2 + x**3 * 69 - r1
    eq1 = y**3 * 420 + x**2 - r2
    ys = eq0.resultant(eq1, x).univariate_polynomial().roots(multiplicities=False)
    y_rems.append([int(i) for i in ys])

from itertools import product
qs = []
for y_rem in product(*y_rems):
    qhi = crt(list(y_rem), primes[1:-1])
    qlo_3 = (r1 - qhi**2) * pow(69, -1, xy_mod) % xy_mod
    qlo_2 = (r2 - qhi**3 * 420) % xy_mod
    qlo = qlo_3 * pow(qlo_2, -1, xy_mod) % xy_mod
    qs.append((qhi << 84) + qlo)

"""
a (Z_i1 * p + Y_i1) + b = Zi*p + Yi
a (Z_i * p + Y_i) + b = Z_i+1 * p + Y_i+1
a ((Z_i - Z_i-1) p + (Y_i - Y_i-1)) == (Z_i+1 - Zi) * p + (Y_i+1 - Y_i)
(Z_i - Z_i-1) p - ainv p (Z_i+1 - Zi) == ainv (Y_i+1 - Y_i) - (Y_i - Y_i-1)
"""
# print([i[0] for i in collect[:20]])
# [1, 2, 3, 5, 7, 9, 11, 12, 13, 14, 15, 17, 18, 20, 22, 25, 26, 27, 28, 29]
# decided to work on [1, 2, 3] as consecutive values

lcg_ys = [sqrt(i[-1]) for i in collect]
sols = []
for q in qs[:1]: # ainv doesnt exist at the other q
    ainv = pow(a, -1, q)
    pp = (-ainv * p) % q
    for y0, y1, y2 in product(*lcg_ys[:3]):
        # optimisation reveals we only need one equation, actually.
        r = (ainv * (y2 - y1) - (y1 - y0)) % q
        M = Matrix([[p ,1,0,0],\
                    [pp,0,1,0],\
                    [r ,0,0,1],\
                    [q ,0,0,0]]) # so smol :3
        M[:,-1] *= 2**40
        for i in range(1):
            M[:,i] *= 2**80
        M = M.LLL()
        for nrow in M:
            if all(i == 0 for i in nrow[:1]) and abs(nrow[-1]) == 2**40:
                if nrow[-1] == 2**40:
                    nrow = [-i for i in nrow]
                sols.append((nrow[1], y0, y1))
print(f'{q = }')

for Z1_minus_Z0, Y0, Y1 in sols:
    Z_0 = (Z1_minus_Z0 * p + Y1 - a * Y0 - b) * pow(a*p-p, -1, q) % q
    if Z_0.bit_length() <= 40:
        X_0 = (Z_0 * p + Y0) % q
        break
# go back one step to recover seed
X_0 = ((X_0 - b) * ainv) % q
state = X_0
print(f'{state = }')

# fast forward for flag
state = (pow(a, 10**18+collect[-1][0]+1, q) * state + (1 - pow(a, 10**18+collect[-1][0]+1, q))*pow(1-a,-1,q)*b) % q

from Crypto.Cipher import AES
from hashlib import sha256
key = sha256(str(state).encode()).digest()
flag = AES.new(key, AES.MODE_ECB).decrypt(bytes.fromhex(ct))
print(flag)
"""
p = 281966007153199959768827186794698649037
a = 210201763039972449186286141207774547530
b = 227313635393666788814653401272488978271
q = 201670286310674408750557303575927151106950475452573
state = 90037349026664929242753260454030385468062012870533
b'deadsec{y0u_p40b4bly_7h1nk_7h15_w45_1n5p1r3d_f40m_cH1m3r4_w311...y0u_a43_n07_wr0n6_3n71431Y}\x04\x04\x04\x04'
"""
```
