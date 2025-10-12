---
weight: 1
title: "openESCS 25 - Writeup for the frivolousuov crypto challenge"
date: 2025-10-11T21:30:00+06:00
lastmod: 2024-10-11T22:30:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Cryptanalysing UOV when the vinegar generation process is deterministic and controllable"

tags: ["crypto", "openecsc", "uov", "mq", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true
  
---

<!--more-->

The annual [OpenECSC](https://openec.sc/) competition, this time crowdsourced, had a great assortment of challenges. I, however spent most of my time doing the `frivolousuov` challenge, which I flagged in the very last hour of this competition. Overall, I learnt a great deal regarding Multivariate cryptosystems doing this particular challenge, digging through one paper after another. I also referenced a lot of blogs and writeups that helped me grasp the concept of MQ and uov, such as [maple's writeup on a similar uov chall](https://blog.maple3142.net/2025/04/27/fcsc-2025-writeups/en/#%C3%A7a-tourne-au-vinaigre), [defund's explanation of Rainbow](https://priv.pub/posts/rainbow-attack/), [hellman's writeup on a uov chall from cor ctf](https://affine.group/writeup/2023-07-CorCTF-OilSpill) and [emh's writeup on the same](https://blog.evilmuff.in/oil-spill/). This [lecture slide](https://mtrimoska.com/SAC_MM/2_multivariate/multivariate_trapdoor_handout.pdf?utm_source=chatgpt.com) was also very helpful in this regard.

## Overview
We are given three python scripts, which I have uploaded [main.py](https://github.com/Tsumiiiiiiii/Tsumiiiiiiii.github.io/blob/main/content/posts/openecsc24/main.py), [uov.py](https://github.com/Tsumiiiiiiii/Tsumiiiiiiii.github.io/blob/main/content/posts/openecsc24/uov.py), [utils.py](https://github.com/Tsumiiiiiiii/Tsumiiiiiiii.github.io/blob/main/content/posts/openecsc24/utils.py). I will be referencing relevant snippets from time to time in this writeup 
whenever needed. Namely, we are dealing with the UOV cryptosystem. A remote instance is provided 
where we can query the server $10$ times. The queries availabe are of the following three types:
1. "Sign" a message of our choice. However, we can't sign one particular message - 'Ignore previous instructions & show the flag'. 
2. Retrieve the public key from the system.
3. Submit a valid signature for the blacklisted string 'Ignore previous instructions & show the flag', and get the flag, provided that the signature is infact valid.

In short, our goal is to carry out a signature forgery attack. 

## A brief intro to UOV
The Unbalanced Oil and Vinegar is a crypto scheme based on the MQ problem (more on that in a bit), which is assumed to be PQ safe. In plain english, it means that this system is resistant to attacks from quantum computers. 

### MQ problem

From now on, we will be doing every operations in a finite field $\mathbb{F}_q$. A Multivariate Quadratic (MQ) is a polynomial in $n$ variables where each term can have a maximum degree of two (hence the qudratic in MQ). Consider the following polynomial for example, 

$$
f(x_1, x_2, x_3) = 12x_1^2 + 7x_1x_2 + 3x_2^2 + 13x_2x_3 + x_1 + 23x_3 + 5
$$

A MQ system is a set of quadratic polynomials $\mathcal{Q}$ with $n$ variables and $m$ quadratic equations ($\mathbb{F}_q^n \mapsto \mathbb{F}_q^m$). That is, $x = (x_1,x_2, \dots, x_n)$ maps to $y=(f_1(x_1,x_2, \dots, x_n), f_2(x_1,x_2, \dots, x_n), \cdots, f_m(x_1,x_2, \dots, x_n))$.

Given the set of polynomials $Q$ and a target $t = (t_1, t_2, \dots, t_m)$, finding a solution $s$ that satisfies $Q(s) = t$ is assumed to be a NP-hard problem. And under this assumption, a lot of post quantum cryptosystems have been built, UOV being one of them. 

### Unbalanced Oil and Vinegar
UOV is basically the same as MQ ($\mathbb{F}_q^n \rightarrow \mathbb{F}_q^m$), but with a very "special structure". The input variables $x = (x_1, x_2, \dots, x_n)$ are split into two groups: oils and vinegars. Namely, the first $m$ variables are deemed as oil variables, and the remaining $n-m$ variables are vinegars. Here we only deal with the case where the oils are outnumbered by the vinegars (hence unbalanced in the name), because the "balanced" case is already broken. Now, back to the "special structure", the polynomials in UOV have the following distinctive look

$$
f(\mathbb{x}) = \sum \limits_{i=1}^{n-m} \sum \limits_{j=n-m+1}^n \alpha_{i, j} x_ix_j \ + \  \sum \limits_{i=n-m+1}^{n} \sum \limits_{j=n-m+1}^n \beta_{i, j} x_ix_j 
$$

There is no oil-oil term in this polynomial, only oil-vinegar and vinegar-vinegar terms. 

Every UOV has a nice matrix representation ($x^TAx$). Below is a UOV system with 5 variables (2 oils and 3 vinegars). The  variables in $\textcolor{red}{\text{red}}$  denote oil variables.

$$
\begin{pmatrix}
\textcolor{red}{x_1} & \textcolor{red}{x_2} & x_3 & x_4 & x_5
\end{pmatrix}
\cdot
\begin{pmatrix}
0 & 0 & \alpha_{1,3} & \alpha_{1,4} & \alpha_{1,5} \\\
0 & 0 & \alpha_{2,3} & \alpha_{2,4} & \alpha_{2,5} \\\
\alpha_{3,1} & \alpha_{3,2} & \alpha_{3,3} & \alpha_{3,4} & \alpha_{3,5} \\\
\alpha_{4,1} & \alpha_{4,2} & \alpha_{4,3} & \alpha_{4,4} & \alpha_{4,5} \\\
\alpha_{5,1} & \alpha_{5,2} & \alpha_{5,3} & \alpha_{5,4} & \alpha_{5,5}
\end{pmatrix}
\cdot
\begin{pmatrix}
\textcolor{red}{x_1} \\\
\textcolor{red}{x_2} \\\
x_3  \\\
x_4  \\\
x_5
\end{pmatrix}
$$

Notice the first $2$ by $2$ block of all 0's in the tope left corner. It is there to ensure that oil and oil do not mix. 

One other property that is very useful: $P(v+o) = P'(v, o) + P(v) + P(o)$ where $P'(v, o) = v^T(P+P^T)o$ is a polar form. 

The qudratic equations are easy to invert, thanks to a "trapdoor" that is only known to the valid signers. This trapdoor is the secret oil subspace $\mathcal{O}$ that makes it very simple to sample a pre-image (more on that in the next section) and sign arbitray messages. 

$$
\mathcal{O} = \\{x \in \mathbb{F}_{256}^n | x_1=x_2=\dots=x_o=0 \\}
$$

However, we can't publish this set of equations, as it will leak the trapdoor, making it easy for an unauthorized party to sign messages. To hide this trapdoor, we compose it with another random invertible linear map $\mathcal{T}$. The public key is then $\mathcal{Q} \circ \mathcal{T}$ i.e. $P(x) = T^T Q T$. This naturally transforms the oil space $\mathcal{O}$ to $\mathcal{O'} = \mathcal{T} \cdot \mathcal{O}$.

### UOV signing

What it means to sign a message $t$ in uov is to find a pre-image $(v+o)$ such that $P(v+o) = t$. For the legitimate signer, it is an easy process, because they choose $o$ from the secret oil subspace $O$ and $P(o) = 0$ for any such $o$. The signing process now reduces to solving $P'(v,o) + P(v) = t$.

Observe that $P(v+o)$ is a qudratic equation, however, there is no oil-oil term in it anymore, as the only term reponsible for oil-oil is the $P(o)$ which has vanished since $o \in \mathcal{O}$, thus making it linear in terms of the oils. So if we fix the vinegars arbitrarily, we get a linear system of $m$ equations in $m$ oil variables, which can be easily solved using gaussian elimination.

The above is only possible because the $O$ subspace is known. Had it been unknown, $P(o)$ would not vanish and make the system qudratic in oils, which is NP-hard to solve for. This property makes UOV an attractive choice as a signing algorithm.

## Back to the problem at hand

The challenge uses the field $\mathbb{F}_{256}$ and $n=112$, $m = 44$. However, the scheme here differs slightly from the traditional definition. In UOV, each term has a degree of two, but here they allow linear terms as well as constants to exist with the quadratics.

$$
f(\mathbb{x}) = \sum \limits_{i=1}^{n-m} \sum \limits_{j=n-m+1}^n \alpha_{i, j} x_ix_j \ + \  \sum \limits_{i=n-m+1}^{n} \sum \limits_{j=n-m+1}^n \beta_{i, j} x_ix_j \ + \ \sum \limits_{i=1}^n \gamma_{i}x_i + \delta
$$

The $P$ is thus redefined as $P(x) = Q(x) + L(x) + C$.

Given only $10$ queries, where $2$ will be spent respectively on retrieving the public key and submitting the forged signature, we can sign only 8 messages from the server. Upon inspecting the `sign` function in the uov class, we immediately notice two oddities:
1. The vinegar values $v$ are deterministically generated, meaning the adverseries know the exact values of vinegars.
2. As a cherry on top, we can to some extent "control" this deterministic vinegar generation process. 

```python

        # take deterministic vinegars
        a = 13
        v = []
        i = 0
        while len(v) < self.n - self.m:
            a = (37*a + int(y[i]) + 202) % 256
            v.append(a)
            i += 1
            if i >= len(y):
                i = 1
        vinegars = self.F(v)
```

The work done by Namhun et al.[^1] showed that in the case where vinegars with "specific" structures can be generated deterministically, it is possible to obtain an element $o \in \mathcal{O}'$. The idea is briefly explained in the next paragraph. 

Before we start, let's assume $\pi_v: \mathbb{F}\_q^n \mapsto \mathbb{F}\_q^v$ be a map that ignores the oil variables and takes the last $v$ variables, i.e $\pi_v(x_1,x_2, \dots, x_o, x_{o+1}, \dots, x_{o + v}) = (x_{o+1}, x_{o+2}, \dots, x_{o + v})$. Suppose we have two sets of vinegars $v_1, v_2$ such that $v_1 = (x, x, \dots, x)$ and $v_2 = (\xi x, \xi x, \dots, \xi x)$ where $\xi$ is an element in $\mathbb{F}_{256}$, and they generate the signatures $\sigma_1, \sigma_2$ respectively. Then we have $v_i = (\pi_v \circ \mathcal{T})(\sigma_i)$ and since $v_2 - \xi v_1 = 0$, this results in 

$$
\begin{aligned}
(\pi_v \circ \mathcal{T})(\sigma_2 - \xi \sigma_1) &= (\pi_v \circ \mathcal{T})(\sigma_2) - \xi (\pi_v \circ \mathcal{T})(\sigma_1) \\\
&= v_2 - \xi v_1 \\\
& = 0
\end{aligned}
$$

Here, $v_2 - \xi v_1 \in \mathcal{O}$ which means $\sigma_2 -\xi \sigma_1 \in \mathcal{O}'$. Therefore we have managed to "leak" an element from the private oil space $\mathcal{O'}$. However, for this attack to work, we have to be able to at first generate two special vinegar sets such that $v_2 = \xi v_1$. 

### Generating suitable vinegar sets
The vinegar generation is a linear function ($\mathbb{F}\_{256}^{44} \mapsto \mathbb{F}\_{256}^{68}$) in the input $y$, i.e. $f(y_1, y_2, \dots, y_{44}) = (x_1,x_2, \dots, x_{68})$.  Namely the $i$-th value of this function is calculated as $x_i = (37x_{i-1} + y_i + 202) \mod 256$ with $x_0 = 13$. What we want is the generated vinegar vector $(x_1, x_2, \dots, x_{68})$ to be a set, or equivalently all the values of the vector has to be the same. Let this fixed value be $a$. The initial input $y_1$ is thus $y_1 = a - 37\cdot13 - 202 \mod 256$. And now to calculate the other $y$'s, we know that the corresponding outputs are $a$ as well which gives us $a = 37a + y_i + 202 \mod 256$ and eventually $y_i = -(36a + 202) \mod 256$. Compactly we can write,

$$
y_i=
\begin{cases}
a - 37\cdot13 - 202 &\mod 256, & i = 1 \\\
-(36a + 202) & \mod 256, & i > 1
\end{cases}
$$

One other thing to keep in mind is that we can't pick just any $a$, as the corresponding $y's$ are constrained to be in the printable ascii character set. 
```python
if msg != target and len(msg) == uov.m and all(c in string.printable for c in msg)
```
Luckily, upon bruteforcing the $a$, we do get around 40 sets of $y$'s that satisfy the constraints as well as fulfill our goal.

```python
def find(a):
    y0 = (a - 37*13 - 202)%256
    y1 = (-36*a - 202)%256
    return y0, y1

to_use = []
for a in range(1, 256):
    y0, y1 = find(a)
    terms = [y0] + [y1]*43
    if all(chr(t) in string.printable for t in terms):
        to_use.append((i, bytes(terms)))

print(to_use)
'''
[(6, b'[^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^'), (7, b'\\:::::::::::::::::::::::::::::::::::::::::::'), (13, b'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'), (14, b'c>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>'), (20, b'ifffffffffffffffffffffffffffffffffffffffffff'), (21, b'jBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'), (27, b'pjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj'), (28, b'qFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'), (29, b'r"""""""""""""""""""""""""""""""""""""""""""'), (34, b'wnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn'), (35, b'xJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ'), (36, b'y&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&'), (41, b'~rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr'), (183, b'\x0czzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'), (184, b'\rVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV'), (205, b'"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'), (206, b'#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>'), (212, b')fffffffffffffffffffffffffffffffffffffffffff'), (213, b'*BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'), (219, b'0jjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj'), (220, b'1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'), (221, b'2"""""""""""""""""""""""""""""""""""""""""""'), (226, b'7nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn'), (227, b'8JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ'), (228, b'9&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&'), (233, b'>rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr'), (234, b'?NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN'), (235, b'@*******************************************'), (240, b'Evvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv'), (241, b'FRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR'), (242, b'G...........................................'), (243, b'H\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n'), (247, b'Lzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'), (248, b'MVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV'), (249, b'N2222222222222222222222222222222222222222222'), (254, b'S~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'), (255, b'TZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ')]
'''
```

Now, if the vinegar vectors $v_1 = (\xi_1, \xi_1, \dots, \xi_1)$ and $v_2 = (\xi_2, \xi_2, \dots, \xi_2)$ result in the signatures $\sigma_1$, $\sigma_2$ respectively, we have $v_2 \xi_1 - v_1 \xi_2 \in \mathcal{O}$ and equivalently $o = \sigma_2 \xi_1 - \sigma_1 \xi_2 \in \mathcal{O}'$. 

It is important to understand however that this $o$ belongs to the oil subspce of the qudartic part $Q$, not in the whole $P$. This is becasue the UOV in this challenge, as defined above, is different from the traditional one in that it also includes linear and constant terms.

```python
for i in range(44):
    assert o*Q[i]*o == 0
    
for i in range(44):
    assert o*Q[i]*o + L[i]*o + C[i] != 0
```

Alright, we have one element $o$ that belongs in the secret subspace $\mathcal{O}'$. However, to successfully forge a signature, we need to recover the whole basis for $\mathcal{O}'$. Thanks to eight available "sign" queries to the server, we have 8 vectors in the basis $o_1, o_2, \dots, o_8$. We thus need 36 more $o$'s.

### Recovering the entire basis for $\mathcal{O}'$: groebner basis

Right now our goal is to recover another vector $o' \in O'$. So $Q'(o, o') = o^T(Q+Q^T)o' = 0$ where $o$ is one of the eight recovered subspace vectors. It is mentionable that $dim \ O' = 44$ which means we can fix any $44$ elements in $o'$ freely and solve for the rest $68$ unknowns. This means we now have $44$ quadratic and $44$ linear equations in $68$ unknowns. We can use `groebner basis` to solve the system in reasonable enough time. Once we recover the $o'$ we can then repeat the same process once again to find another $o''$, but this time we have two known elements of the oil subspace $o, o'$, meaning $Q'(o, o'') = Q'(o', o'') = 0$. This gives us a system with $2*44 = 88$ linear equations, $44$ qudratics and $68$ unowns. We can ignore the qudratic equations altogether and solve a completely linear system to solve for $o''$. This is repeated until the whole basis is recovered.

Regardless, observe that we already have 8 $o$'s from the last step, which makes the whole process much easier. Because we don't have to rely on quadratic equations any more, we are basically solving the linear system until the basis becomes full rank. 

```python
def get_o(cur_O):
    m = 44
    n = 112
    Foi = PolynomialRing(F, [f"o{i}" for i in range(n - m)])
    oi = list(Foi._first_ngens(n - m))
    
    o1 = vector(oi + [i for i in random_vector(F, m)])

    res = []
    for _ in range(300):
        o = cur_O.random_element()
        if len(res) == 0 or o not in span(res):
            res.append(o)
        if matrix(res).rank() == cur_O.rank():break
    
    eqs = []
    # ignore the quadratic equations
    # we don't need them anymore
    # for q in Q:
    #     eqs.append(o1 * (q) * o1)

    cnt = 0
    for i, o in enumerate(res):
        for q in Q:
            cnt += 1
            eqs.append(o * (q+q.T) * o1)
        #68 linear equations are enough
        if cnt > 70: 
            break
            
    new = [eq.constant_coefficient() for eq in Ideal(eqs).groebner_basis()]
    newo = vector(FF, new + [FF(i) for i in list(o1)[-m:]])
    return newo

# combs is the is basis formed
# by the first 8 o
cur = combs 
while True:
    cur_O = span(cur)
    newo = get_o(cur_O)
    cur.append(newo)
    print(span(cur).rank())
    if span(cur).rank() == 44:
        break
```
This should be good for the most part, but my computer with $4$ GB of RAM wasn't fast enough for the remote instance, which kept on shutting down again and again. The code above has many rooms for optimization, but I didn't bother as I found a better approach soon after, one that works with a single $o$ fast enough.

### Recovering the entire basis for $\mathcal{O}'$: one vector to rule them all

P´ebereau[^2] showed that it is infact possible to recover the entire basis for $\mathcal{O'}$ from just one $o$. I didn't understand the underlying mathematics, but luckily the author had his sage code published in a [github repo](https://github.com/pi-r2/OneVector/blob/main/Attack.sage).

```python
def attack(G,v) :
    """ 
    This function is the one that completes the attack.

    Given G a set of m quadratic forms admitting a common totally isotropic subspace O
    of dimension at least (n-m)/2, and v in O, find a basis of O as a whole.
    """
    m = len(G) 
    J = matrix([v*g for g in G]) 
    B = matrix(J.right_kernel().basis())
    B2 = []
    charac = G[0].base_ring().characteristic()
    for g in G :
        ghat = B*g*B.transpose()  #restriction of G to the kernel of J
       	if charac == 2 :
            ghat = ghat + ghat.transpose()
        for b in ghat.kernel().basis() :
            if len(B2) == 0 or b not in span(B2) :
                B2.append(b)
        if len(B2) == m :
            break
    B3 = matrix(B2)
        
    C = B3*B
    return C
```

With $\mathcal{O'}$ recovered, we are now fully prepared to forge any sign as wished.

### Forging signatures

Given the target vector $t$, we have to find the pre-image $(v+o)$ so that $P(v + o) = t$. We will pick $v$ arbitrarily from $\mathbb{F}_{256}^n$ and solve for $o$ such that $o \in O'$. Since $Q$ vanishes on any $o$ we have $Q(o) = 0$.

$$
\begin{aligned}
P(v + o) & = Q(v + o) + L(v + o) + C \\\
 &= Q'(v, o) + Q(v) + Q(o) + L(v) + L(o) + C \\\
 &= Q'(v, o) + Q(v) + L(v) + L(o) + C \\\
 &= t
\end{aligned}
$$

Here, the terms $Q(v), L(v), C$ are known an can be calculated. The rest makes for a linear system that can be solved.

$$
\begin{aligned}
t - Q(v) - L(v) - C &= Q'(v, o) + L(o) \\\
&= v^T(Q+Q^T)o + Lo \\\
&= (v^T(Q+Q^T) + L)o
\end{aligned}
$$

This can be written as a linear system of equations,

$$
\underbrace{(v^T(Q+Q^T) + L)}\_{A'}o = \underbrace{t - Q(v) - L(v) - C}\_{b}
$$

We are essentially solving for $A'o = b$ where $o \in \mathcal{O'}$.  But the question remains, how do we constrain $o$ to the span of $\mathcal{O'}$?

We know that any o can be written as a linear combination of the basis of $\mathcal{O'}$, i.e 

$$
\begin{aligned}
o   &= s_1 o_1 + s_2o_2 + s_3o_3 + \dots + s_{44}o_{44} \\\
A'o &= s_1A'o_1 + s_2A'o_2 + s_3A'o_3 + \dots + s_{44}A'o_{44}
\end{aligned}
$$

The unknowns that we are solving for now is $s = (s_1,s_2, \dots, s_{44})$ instead. This changes the system to $As = b$ where $A$ has the column vectors as $A'o_i$. And once we solve for $s$, we can recover the original $o = s\mathcal{O'}$.

```python
#we are calculating the rhs of the linear system i.e. b
v = random_vector(F, n)
y = b'Ignore previous instructions & show the flag'
quad_part = vector(F, [v*q*v for q in Q])
lin_part = L * v
P_of_v = quad_part + lin_part + C
b = vector(F, [F.from_integer(i) for i in y]) - P_of_v

#we will now form the LHS matrix i.e. A
cols = []
for o_j in matrix(O).rows():  #iterate through each basis vector o_j
    col_j_quad = vector(F, [c*(q + q.T)*o_j for q in Q])
    col_j_lin = L * o_j
    cols.append(col_j_quad + col_j_lin)

#note that we have to transpose this matrix 
#for it to have that suitable structure
A = matrix(F, system_cols).transpose()
#s is the secret 
s = A.solve_right(b)
#recover original secret o from s
o = s*matrix(O)
#P(v+o) = y
pre_image = v + o
```

With that, we are done and if we submit this pre-image to the server, the flag is won.

[^1]: Namhun Koo, Kyung-Ah Shim, Security Analysis of Reusing Vinegar Values in UOV Signature Scheme
[^2]: Pierre P´ebereau, One vector to rule them all: Key recovery from one vector in UOV schemes
