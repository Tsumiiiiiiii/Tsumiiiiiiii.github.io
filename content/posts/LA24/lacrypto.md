---
weight: 1
title: "LA CTF 2024 crypto writeups"
date: 2024-02-25T00:37:00+06:00
lastmod: 2024-02-25T00:37:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for some Cryptography challenges from LA24."

tags: ["crypto", "LA CTF", "LCG", "zk", "dlog", "CRT", "pohlig-hellman", "blum-micali", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true


---

Writeup for some Cryptography challenges from LA CTF 24.


<!--more-->

## prove it!

From the name and the description we get the hint that this problem is about zk-snarks. Though we can solve this problem without even knowing what zero-knowledge proof is. This is the script that we are provided with:

```python
#!/usr/local/bin/python
import random

flag = "lactf{??????????}"
p = 171687271187362402858253153317226779412519708415758861260173615154794651529095285554559087769129718750696204276854381696836947720354758929262422945910586370154930700427498878225153794722572909742395687687136063410003254320613429926120729809300639276228416026933793038009939497928563523775713932771366072739767


if __name__ == "__main__":
    
	s = random.getrandbits(128)
	alpha = random.getrandbits(40)
	g = redacted
	ss = [pow(g, s**i, p) for i in range(1,8)]
	alphas = [pow(g, alpha * s**i, p) for i in range(1,8)]
	print(f"Use these values to evaluate your polynomials on s")
	print(f"Powers of s: {ss}")
	print(f"Powers of alpha*s: {alphas}")
	tries = 0
	while True:
		if tries >= 2:
			print("Fool me once shame on you, fool me twice shame on me")
			break
		print("Can you prove to me you know the polynomial f that im thinking of?")
		target = []
		for i in range(8):
			target.append(random.randrange(p))
		print(f"Coefficients of target polynomial: {target}")
		ts = sum([(pow(s,7 - i, p) * target[i]) % p for i in range(len(target))]) % p
		f = int(input("give me your evaluation of f(s) > ")) % p
		h = int(input("give me your evaluation of h(s) > ")) % p
		fa = int(input("give me your evaluation of f(alpha * s) > ")) % p
		if f <= 1 or h <= 1 or fa <=1 or f == p-1 or h == p-1 or fa == p-1:
			print("nope")
			exit()
			
		if pow(f, alpha, p) != fa or f != pow(h, ts, p):
			print(f"failed! The target was {ts}")
			tries += 1
			continue
	
		print(f"you made it! here you got {flag}")
		break
```


The program flow is as follows:

1. A prime $p$ is given which is always fixed.
2. $s$ is a $128 \ bit$ variable and $\alpha$ is a $40 \ bit$ variable generated randomly and kept secret. $g$ is also a secret but always fixed.
3. Two public arrays are generated. $ss = g^{s^1}, g^{s^2}, \cdots, g^{s^8} \mod p$ and $alphas = g^{\alpha \cdot \ s^1}, g^{\alpha \cdot \ s^2}, \cdots, g^{\alpha \cdot \ s^8} \mod p$.
4. Then we are given two rounds where for each round, 
   1. A public array $target$ of length 8 is randomly generated where each value is within the range of $p$. 
   2. A private value $ts$ is calculated as $ts=\sum_{i=0}^7 s^{7-i} \cdot target_i \mod p$. 
   3. We have to provide the value for 3 variables $f, fa, h$ such that $f^{\alpha} \equiv fa \mod p$ and $h^{ts} \equiv f \mod p$. To stop cheesing, there are some further restrictions on the values: they must be in the range $[2, p-2]$ inclusive. 
   4. If we lose the round, the private value $ts$ is revealed. If we win, the flag is revealed.


My solution comprised of two steps:
1. Recover $\alpha$ using `discrete log`.
2. Recover $s$ using the polynomial modular equation solver of `sage-math`.


#### Recover $\alpha$

As I have already spoiled, we are going to apply `dlog` for this step. But we don't even know $g$. What do we do now? Let, 

$$
\begin{aligned}
b' &\equiv \frac{ss_2}{ss_1} &\equiv \frac{g^{s^2}}{g^s} &\equiv g^{s^2 - s} & \mod p \\\
b'' &\equiv \frac{alphas_2}{alphas_1} &\equiv \frac{g^{\alpha \cdot s^2}}{g^{\alpha \cdot \ s}} &\equiv g^{\alpha \cdot \ (s^2 - s)} & \mod p \\\
\rightarrow b'' & \equiv(b')^{\alpha} &&& \mod p
\end{aligned}
$$

Since we know both $b''$ and $b'$,  $g$ becomes irrelevant.  We can shift our focus solely on solving the `dlog` $b'' \equiv (b')^{\alpha}$ now. But $p$ is a $1024 \ bit$ prime. Maybe the group order is smooth? Upon checking on `factor-db`, we get a very interesting insight

$$
p - 1 =  2 × \underbrace{7 × 13 × 19 × 53 × 1777 × 13873}\_{\text{42 \ bits}} × 375066 324492 304430 531233 × 101 \cdots 063
$$

$\alpha$ is $40 \ bits$. Hurray 😂, we do have a sub-group small enough to solve the `dlog` efficiently. The largest prime there ($13873$) is just $14 \ bits$.  We don't even need `baby-steps-giant-steps`,  literally brute forcing would suffice for each prime. Finally, we can combine each `log` using `crt` and recover the original $\alpha$. 

```python
F = GF(p)

def discrete_log(y, g, f):
    for pw in range(f):
        y_ = pow(g, pw, f)
        if y == y_:
            return pw
    return -1

values = []
mods = []
for f in fs:
    o = (p-1) // f
    Pg = F(b_)^o
    Py = F(b__)^o
    r = discrete_log(Py, Pg, f)
    if r > -1: 
        mods.append(f)
        values.append(r)
    
print('found', crt(values, mods))
```


{{< admonition type=warning title="Be aware" open=true >}} 
Sometimes the b'' itself might lie in the subgroup of the smaller primes. We can't do `dlog` in that case. That is why we can try using all the $ss_i, alphas_i$ pairs, or keep running the instance until a suitable $ss_0, alphas_0$ pair appears.
{{< /admonition >}}


#### Recover $s$

The plan is to *sacrifice* the first round so that we can get $ts$. $s$ is **fixed** for both rounds, which means if we manage to recover $s$ now, we can win the second round.

$$ts=s^7 \cdot target_0 + s^6 \cdot target_1 + \cdots + s^0 \cdot target_7 \mod p$$ 
No big brain 🧠 move is necessary here. Just use `sage-math` and profit !!

```python
P.<x> = PolynomialRing(Zmod(p))
f = sum(x^(7-i)*target[i] for i in range(8))
f -= ts
f = f.monic()
f.roots()
```


#### Recover $flag$

Since we know both $\alpha$ and $s$ now, on the second round we can send  $f^{\alpha} \equiv fa \mod p$ and $h^{ts} \equiv f \mod p$ and $h=5$ to successfully retrieve the flag. 

> **lactf{2kp_1s_ov3rr4t3d}**

---



## shuffle

My favorite problem of the year so far. The idea is simple but elegant. Thanks to the author ❤. This is the script we are given:

```python
#!/usr/local/bin/python3

from secrets import randbits
import math
from base64 import b64encode
MESSAGE_LENGTH = 617

class LCG:

    def __init__(self,a,c,m,seed):
        self.a = a
        self.c = c
        self.m = m
        self.state = seed

    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

def generate_random_quad():
    return randbits(64),randbits(64),randbits(64),randbits(64)

initial_iters = randbits(16)

def encrypt_msg(msg, params):
    global initial_iters
    a, c, m, seed = params
    L = LCG(a, c, m, seed)
    for i in range(initial_iters):
        L.next()
    l = len(msg)
    permutation = []
    chosen_nums = set()
    while len(permutation) < l:
        pos = L.next() % l
        if pos not in chosen_nums:
            permutation.append(pos)
            chosen_nums.add(pos)
    output = ''.join([msg[i] for i in permutation])
    return output

# period is necessary
secret = b64encode(open('secret_message.txt','rb').read().strip()).decode() + '.'
length = len(secret)
assert(length == MESSAGE_LENGTH)

a, c, m, seed = params = generate_random_quad()
enc_secret = encrypt_msg(secret,params)

while True:
    choice = input("What do you want to do?\n1: Shuffle a message.\n2: Get the encrypted secret.\n3: Quit.\n> ")
    if choice == "1":
        message = input("Ok. What do you have to say?\n")
        if (len(message) >= length):
            print("I ain't reading allat.\n")
        elif (math.gcd(len(message),m) != 1):
            print("Are you trying to hack me?\n")
        else:
            print(f"Here you go: {encrypt_msg(message,params)}\n")
    elif choice == "2":
        print(f"Here you go: {enc_secret}\n")
    elif choice == "3":
        print("bye bye")
        exit(0)
    else:
        print("Bad choice.\n")
```


The outer program flow is easy to understand. Let us try to see what happens in the `encrypt_msg` function. 

1. An object called `LCG` is generated with fixed params `a, c, m, seed`.
2. The `LCG` state is progressed a fixed amount of times (`initial_iter` times to be exact).
3. The next states are used to encrypt the message.
4. The encryption here is simply a *permutation* operation. `pos = L.next() % l` and in this way, the entire message is shuffled and returned. 
5. There is a *catch*. If there is a repetition of `pos`, then that value is discarded and the next state is evaluated. 

### Understanding `LCG`

`Linear Congruential Generator` or `LCG` denotes a linear function used for generating random numbers. It can be denoted with a recursive function as follows:

$$X_{n+1} = a \cdot X_n + c \mod m$$

Here, 

* `a` is the multiplier
* `c` is the increment
* `m` is the modulo which is generally a prime
* $X_1, X_2, \cdots, X_n$ are the states, with $X_0$ being the initial state or the `seed`

Suppose we don't know $a, c, m, seed$ (which is the case for the given problem as well) but we somehow managed to get our hands on 6 consecutive states of the `LCG` ($X_n, X_{n+1}, \cdots, X_{n+5}$), we have a process to recover $a, c, m$ from them.

#### Recover the modulo `m`

Suppose we know the states $X_1, X_2, \cdots, X_6$. 

$$
\begin{aligned}
X_1 &\equiv a \cdot X_0 + c &\mod m \\\ 
X_2 &\equiv a \cdot X_1 + c &\mod m \\\ 
\vdots \\\
X_6 &\equiv a \cdot X_5 + c &\mod m \\\ 
\end{aligned}
$$

For each consecutive pair of equations, we can subtract the first from the second to get

$$
\begin{aligned}
T_0 \rightarrow X_2 - X_1 & \equiv a \cdot (X_1 - X_0) &\mod m \\\
T_1 \rightarrow X_3 - X_2 & \equiv a \cdot (X_2 - X_1) &\mod m \\\
T_2 \rightarrow X_4 - X_3 & \equiv a \cdot (X_3 - X_2) &\mod m \\\
T_3 \rightarrow X_5 - X_4 & \equiv a \cdot (X_4 - X_3) &\mod m \\\
T_4 \rightarrow X_6 - X_5 & \equiv a \cdot (X_5 - X_4) &\mod m
\end{aligned}
$$

We can divide each consecutive pair of $T$ to cut off the $a$ term.

$$
\begin{aligned}
\frac{T_1}{T_2} &\equiv \frac{X_3 - X_2}{X_4 - X3} \equiv \frac{X_2 - X_1}{X_3 - X_2} &\mod m \\\
\rightarrow \frac{T_1}{T_2} &\equiv \frac{X_2 - X_1}{X_3 - X_2} &\mod m \\\
\rightarrow \frac{T_1}{T_2} &\equiv \frac{T_0}{T_1} &\mod m \\\
\rightarrow T_1 ^ 2 &\equiv T_0 \cdot T_2 &\mod m \\\
\rightarrow T1^2 - T_0 \cdot T_2 &= k_1 \cdot m
\end{aligned}
$$

Similarly, we can write

$$
\begin{aligned}
T2^2 - T_1  \cdot T_3 &= k_2 \cdot m \\\
T3^2 - T_2  \cdot T_4 &= k_3 \cdot m
\end{aligned}
$$

If we take the `gcd` of these 3 terms, what we get is

$$GCD(k_1 \cdot m, k_2 \cdot m, k_3 \cdot m) = m $$

 It might be the case that $k_1, k_2, k_3$ shares a common factor then we will be getting a multiple of $m$. But even if that is the case, the multiple is going to be so *small* that we can do some trial division and eliminate that multiple.

#### Recover the multiplier `a` and the increment `c`

Since we do know $m$ now, it becomes trivial to recover $a$ and $c$.

$$
\begin{aligned}
a &\equiv \frac{X_3 - X_2}{X_2 - X_1} &\mod m \\\
c &\equiv X_2 - a \cdot X_1 &\mod m
\end{aligned}
$$

We can use the below script(that I collected from another writeup last year) to crack the `LCG` parameters.

```python
from functools import reduce

def modinv(x, p):
    return pow(x, -1, p)

def crack_unknown_increment(states, modulus, multiplier):
    increment = (states[1] - states[0] * multiplier) % modulus
    return modulus, multiplier, increment

def crack_unknown_multiplier(states, modulus):
    multiplier = (states[2] - states[1]) * modinv(states[1] - states[0], modulus) % modulus
    return crack_unknown_increment(states, modulus, multiplier)


def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2 * t0 - t1 * t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))
    return crack_unknown_multiplier(states, modulus)
```


### Tackling the given problem

We know how to crack `LCG` and we also know we have to recover 6 *consecutive* states of the `LCG` first. Suppose `initial iters` is $n$, so every time we query for a message $m$, the states $X_n, X_{n+1}, X_{n+2}, \cdots, X_{n + sz - 1}$ is used. Since we are concerned with 6 states only, we need $X_{n+1}, X_{n+2}, \cdots, X_{n+5}$ only. (For the time being, I am going to assume that no repetitions will occur and hence no state will be skipped). 

As test, we send `message = abcdefg`.

<kbd> <img src="https://github.com/Tsumiiiiiiii/Tsumiiiiiiii.github.io/blob/main/content/posts/LA24/shuffle.png?raw=true"
 style="border-radius:2%" align="center" width = "100%" /> </kbd>

From the last table, we can deduce the following equations:

$$
\begin{aligned}
X_{n} &\equiv 5 &\mod 7 \\\
X_{n + 1} &\equiv 3 &\mod 7 \\\
X_{n + 2} &\equiv 6 &\mod 7 \\\
\vdots \\\
X_{n + 6} &\equiv 1 &\mod 7 \\\
\end{aligned}
$$

Not bad, we have a *tiny* portion of $X_n, \cdots, X_{n+5}$ ( i.e. $X_i \mod 7)$. As $X_i$ is a $64 \ bit$ number, we need $X_i \mod \ a \ 65 \ bit \ number$ to recover the original $X_i$. 

We can repeat the same process for $m = 7, 11, 13, 17, \cdots$ until the product of the $mods$ is big enough. Suppose we have this:

$$
\underbrace{X_n \mod (7 \cdot 11 \cdot 13 \cdots \cdot 67)}\_{\text{CRT}}
\begin{cases}
\begin{aligned}
X_{n} &\equiv 5 &\mod 7 \\\
X_{n} &\equiv 8 &\mod 11 \\\
X_{n} &\equiv 2 &\mod 13 \\\
\vdots \\\
X_{n} &\equiv 43 &\mod 67
\end{aligned}
\end{cases}
$$

In the same way, we can use `chinese-remainder-theorem` or `CRT` to recover $X_{n+1}, \cdots, X_{n+5}$ as well. 

As the characters in each message that we send must be unique and printable, we send characters from the ASCII range $33$ to $127$. That is, for a message of length $k$, we send: $message_k = ascii_{33} + ascii_{33+1} + ascii_{33+2} + \cdots + ascii_{33 + k - 1}$. 

#### But are all the states actually *consecutive*?

Remember the assumption I made earlier? *For the time being, I am going to assume that no repetitions will occur and hence no state will be skipped*. This rarely holds. In *almost* all of the cases, there will be some states that will be skipped. And if that happens, the `LCG` solver will return some garbage value that will be easy to understand. I ran a simulation to check how frequent that is and printed `m, a, c`.

```shell
4 0 3
1 0 0
1 0 0
1 0 0
4 0 3
1 0 0
1 0 0
1 0 0
5 0 2
1 0 0
1 0 0
1 0 0
1 0 0
1 0 0
1 0 0
1 0 0
1 0 0
4 2 3
5817747651381476157 3630784695756569456 5646245808023284019
```

For all skip cases, it gave values that were impossible (very small values). But in the last line, we can see a *lucky* case where no state was skipped and we get a value that is large enough(around $64 \ bits)$.  On average, after every $15$ to $20$ run, we get a *lucky* case like that. That is when we progress our solve and for other cases, we skip and move on to the next. 

```python
from base64 import b64decode

for _ in range(100):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('chall.lac.tf', 31172))

    opts = ''.join(chr(c) for c in range(33, 128))

    def get_enc_msg(p):
        recvuntil(sock, b'> ')
        sendline(sock, b'1')
        recvline(sock)
        to_send = (opts[:p]).encode()
        sendline(sock, to_send)
        line = recvline(sock).decode().strip()
        if ':' not in line:
            return None
        else:
            return line.split(': ')[1].replace(' ', '')

    def get_idx_from_perm(s, o):
        return [o.index(c) for c in s]

    p = 38
    tot_mod = 1
    mods = []
    perms = []

    while True:
        if int(tot_mod).bit_length() > 64:
            break

        while not is_prime(p): p += 1

        r = get_enc_msg(p)
        if r:
            tot_mod *= p
            mods.append(p)
            perms.append(get_idx_from_perm(r, opts[:p])[:6])

        p += 1


    lcg_states = []

    for pos in range(6):
        vals = []
        for i in range(len(perms)):
            vals.append(perms[i][pos])

        lcg_states.append(CRT(vals, mods))

    try:
        m, a, c = crack_unknown_modulus(lcg_states)
        print(m, a, c)
    except:
        continue
        
    if min([int(m).bit_length(), int(a).bit_length(), int(c).bit_length()]) < 20:
        continue

    recvuntil(sock, b'> ')
    sendline(sock, b'2')
    enc = recvline(sock).decode().strip().split(': ')[1].replace(' ', '')


    class LCG:

        def __init__(self,a,c,m,seed):
            self.a = a
            self.c = c
            self.m = m
            self.state = seed

        def next(self):
            self.state = (self.a * self.state + self.c) % self.m
            return self.state

    L = LCG(a, c, m, lcg_states[-1])
    prev = (lcg_states[0] - c + m) % m
    prev = (prev * pow(a, -1, m)) % m

    L = LCG(a, c, m, prev)

    permutation = []

    l = 617
    chosen_nums = set()
    while len(permutation) < l:
        pos = int(L.next()) % l
        if pos not in chosen_nums:
            permutation.append(pos)
            chosen_nums.add(pos)

    msg = ['!' for _ in range(l)]
    for i, v in enumerate(permutation):
        msg[v] = enc[i]

    msg = ''.join(c for c in msg)
    print(b64decode(msg))
      
```

```shell
b'I just invented the best shuffling algorithm!\nNobody can read this!\nHere, let me hide a flag here: lactf{th3_h0us3_c0uld_n3v3r_l0se_r1ght}\nI better not see anyone try to lay their three fingers sideways (mod m) and declare "with this breath, I determine a to be congruent to (X_2 - X_3)/(X_2 - X_1) and c to be trivial"\nI mean, it\'s surely impossible to decipher this message right\nI\'m going to sell this algorithm to every casino ever and get rich mwahahahaha'
```

> **lactf{th3_h0us3_c0uld_n3v3r_l0se_r1ght}**

---

## pprngc

This was a simpler, yet refreshing challenge which requires no knowledge of mathematics or algorithms. The given script is:

```python
#!/usr/local/bin/python3

import secrets
from super_secret_stuff import flag, f, f_inverse

seed = secrets.randbits(16)
function_uses = 0
oracle_uses = 0
done = False

def compute_output_bit(state, pred):
    return bin((state & pred)).count("1") % 2

def prng(pred):
    cur_state = seed
    outputs = []
    for i in range(16):
        cur_state = f(cur_state)
        outputs.append(compute_output_bit(cur_state, pred))
    cur_state = f(cur_state)
    cur_state_bits = format(cur_state, 'b').zfill(16)
    all_bits = ("".join([str(i) for i in outputs]) + cur_state_bits)[::-1]
    return all_bits

def pprngc(pred, stream):
    state = int("".join(stream[:16][::-1]), 2)
    for i in range(16, len(stream)):
        state = f_inverse(state)
        if not compute_output_bit(state, pred) == int(stream[i]):
            return None
    state = f_inverse(state)
    return compute_output_bit(state, pred)

print("All you need to know about f is that it's a function from 16 bits to 16 bits")
print("The output on today's secret seed is:", f(seed))
if __name__ == "__main__":
    while not done:
        choice = input("What can I do for you? 1. get random bits 2. use f 3. predict next bit 4. guess seed ").strip()
        if choice == "1":
            rand_pred = secrets.randbelow(2**16)
            output = prng(rand_pred)
            print(output)
            print("Using predicate", rand_pred)
            print("Ignore the fact that the first 16 bits are always the same (or don't, your choice)")
        elif choice == "2":
            if function_uses == 15:
                print("Nah, you've had enough.")
                continue
            num = input("Gimme a number! ").strip()
            try:
                num = int(num)
                if num < 0 or num >= 2**16:
                    print("Out of range!")
                else:
                    print(f(num))
                    function_uses += 1
            except:
                print("Uh something went wrong.")
        elif choice == "3":
            if oracle_uses == 16:
                print("Nah, you've had enough.")
                continue
            stream = input("Gimme the bitstream you want to predict! ").strip()
            if len(stream) < 16:
                print("Out of range!")
            else:
                pred = input("Oh, can you also give a predicate with that? ").strip()
                try:
                    pred = int(pred)
                    if pred < 0 or pred >= 2 ** 64:
                        print("Out of range!")
                    else:
                        output = pprngc(pred, stream)
                        if output is None:
                            print("Uh lemme get back to you on that...")
                            print("*liquidates assets, purchases fake identity, buys one way ticket to Brazil*")
                            done = True
                        else:
                            print(output)
                            oracle_uses += 1
                except:
                    print("Uh something went wrong.")
        elif choice == "4":
            guess = input("Well, let's see it! ").strip()
            if str(seed) == guess:
                print(flag)
            else:
                print("Nope! Sorry!")
            done = True
        else:
            print("Buh bye!")
            done = True
```
<br/>

We have a function $f$ which we have no idea about. All we are told is that it maps 16 bits to 16 bits. And at the beginning, we are given $f(seed)$. We have to guess $seed$ using queries of the following types:

1. Generates a random `predicate` of $16 \ bit$ length and inputs it to a function called `prng`. It gives us $f^{17}(seed)$ and the output of another function called `compute_output_bit`. Can be used as many times as wanted.
2.  Inputs $num$ and outputs $f^{15}(num)$. Can be used 15 times only.
3.  Takes a $predicate$ and a $bit \ stream$ from the user and passes it as input to a function called `pprngc`. This function is *almost* the opposite of function $prng$. Can be used 16 times.
4.  Gives a chance to guess the $seed$. If we are successful, we are given the flag.

<br/>

`pprngc` function gives us $(f^{-1})^{17}(pred)$. Well not exactly, it passes that output through a function  called `compute_output_bits` and then gives it to us. Let us have a closer look at that particular function. 
1. Takes as input two parameters called $state$ and $pred$.
2. Computes $x = states \ \\& \ pred$.
3. Calculates how many *on* bits ($1 \ bit$) are there in $x$.
4. If the parity is even, return $1$, else return $0$.

We can use it as an oracle to leak bits at any position we want! 

<br/>

### `compute_output_bits` as a bit leaking oracle

Suppose we want to leak the *lsb* (1st bit from the right) of $state$.  I am going to use $8 \ bit$ numbers as examples here. 
1. The *lsb* is 1. $state := 01001101$ and $pred := 00000001$. In that case, $state \ \\& \ pred = 00000001$. The parity of $1$ count is **odd**.
2. The *lsb* is 0. $state := 01001100$ and $pred := 00000001$. In that case, $state \ \\& \ pred = 00000000$. The parity of $1$ count is **even**.

<br/>

Now why does this happen? The $7$ off-bits in $pred$ forces all initial $7$ bits in the "$\&$" operation to be 0. The remaining bit depends on *lsb* of $state$. In this way, we can leak any bit of $state$. What would the $pred$ be if we wanted to leak the bit at the $4-th$  position? $pred := 00001000$. This would force all other bits to be $0$, except on the $4-th$ position, where it depends on the $state$. 

<br/>

### Thinking of a solution

We need to somehow backtrack $f(seed)$ to $seed$. Maybe using `pprngc`?. But wait, it will give us $(f^{-1})^{17}(f(seed)) \rightarrow (f^{-1})^{16}(seed)$ instead. But if we could provide it, $f^{17}(seed)$, then it would give us  $(f^{-1})^{17}(f^{17}(seed)) \rightarrow seed$. It would give `count_output_bit` of $seed$ but we have already seen how to use it to leak every bit of $state$ (which in this case happens to be $seed$). 

#### Recovering upto $f^{17}(seed)$

We can use the $2nd$ query 15 times on $f(seed)$ to get $f^2(seed), f^3(seed), \cdots, f^{16}(seed)$. 

But this isn't good enough, we still need $f^{17}(seed)$. This is where the $1st$ type of query comes in. The output of that query is always going to contain $f^{17}(seed)$, along with some bit streams generated by `count_output_bit` that are not necessary now.

#### Recovering the $seed$

Now this question might come to your mind if we could obtain $f^{17}(seed)$, why do we need $f^2(seed), \cdots, f^{16}(seed)$? Actually, when we use the `pprngc` function, it deploys some verification mechanism that checks whether we know all the states of $seed$ in the line `if not compute_output_bit(state, pred) == int(stream[i]):`

With all setup, we send the $f^{17}(seed)$ and the $stream$ bit stream along with suitable $pred$ to leak bits at all positions!!

<br/>

```python
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('chall.lac.tf', 31173))

states = []

recvline(sock)
s1 = int(recvline(sock).decode().strip().split(': ')[1])
states.append(s1)

for i in range(15):
    recvuntil(sock, b'seed ')
    sendline(sock, b'2')
    recvuntil(sock, b'! ')
    sendline(sock, str(states[-1]).encode())
    s = int(recvline(sock).decode().strip())
    states.append(s)
    
print(states)
    
recvuntil(sock, b'seed ')
sendline(sock, b'1')
output = recvline(sock).decode().strip()
recvline(sock)
recvline(sock)

s17 = output[:16]

print(output)

def compute_output_bit(state, pred):
    return bin((state & pred)).count("1") % 2

def get_prediction(pos):
    bits = ['0' for _ in range(16)]
    bits[pos] = '1'
    bits = int(''.join(c for c in bits), 2)
    ret = ''
    for s in states:
        ret += str(compute_output_bit(s, bits))
    return bits, ret[::-1]

seed = ['1' for _ in range(16)]
for pos in range(16):
    pred, seq = get_prediction(pos)
    seq = s17 + seq
    
    recvuntil(sock, b'seed ')
    sendline(sock, b'3')
    recvuntil(sock, b'! ')
    sendline(sock, seq.encode())
    recvuntil(sock, b'? ')
    sendline(sock, str(pred).encode())
    b = recvline(sock).decode().strip()
    print(b)
    seed[pos] = b
    

seed = int(''.join(c for c in seed), 2)
print(seed)
    
recvuntil(sock, b'seed ')
sendline(sock, b'4')
recvuntil(sock, b'! ')

sendline(sock, str(seed).encode())
print(recvline(sock))
```

> **lactf{we_love_blum-micali_generators_h1MNZuJSFjlAEwc1}**


