---
weight: 1
title: "Backdoor CTF 2023 - Cryptography Writeups"
date: 2023-12-26T11:02:00+06:00
lastmod: 2023-12-26T11:02:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for some Cryptography challenges."

tags: ["crypto", "ECC", "mitm", "polynomials", "Backdoor CTF", "english"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---

Writeup for some Cryptography challenges.

<!--more-->



## Something in common

We start by checking the `script.py` script given to us:

```python
from Crypto.Util.number import *

flag = "This flag has been REDACTED"
moduli = "This array has been REDACTED"

m = bytes_to_long(flag.encode())
e = 3
remainders = [pow(m,e,n) for n in moduli]

f = open('output.txt','w')
for i in range(len(moduli)):
    f.write(f"m ^ e mod {moduli[i]} = {remainders[i]}\n")
f.write(f"\ne = {e}")
f.close()
```

We are also provided with the `output.txt` file which contains 7 $moduli$, $remainder$ pair. So, what we are given is:

$$m^3 \equiv  c_1 \mod n_1$$


$$m^3 \equiv  c_2 \mod n_2$$

$$\vdots$$

$$m^3 \equiv  c_7 \mod n_7$$

Here, the $c_i$, $n_i$ pairs are known. We need to find $m$. This is a very classic problem called the broadcast attack. If we take the `chinese remainder theorem` of the pairs, what we are going to get is:

$$ m^3 \equiv c \mod (n_1 * n_2 * \ldots * n_7 ) $$

What happens in such cases is that, the modulo(which is the product of all the $n_i$) is much bigger than $m^3$. 

$$ m^3 << c$$

$$m << \sqrt[3] c$$

Thus, just taking `cube-root` of the resulting $c$ yields the message.

```python
from gmpy2 import iroot

m1, v1 = 231689896592553079225008346159565141292942746185614335113030628126523977770897610833 ,70932244057518414814271820586538428333420562252483260602196856595136636875881109254
m2, v2 = 7171431858055720778675521 ,6776581747370220150625940
m3, v3 = 66926822362327139196541990168817936306935699 , 48565469191356626147008517582743644359421796
m4, v4 = 437335592290538364420374052921942150635299817629860400585996176158735283605573507708521 , 8794419984130129081066440741470891653922464557881503503363167507918405790466608773101
m5, v5 = 289641633885807692370107575915133663791 , 172864555741817549854149625512946760571
m6, v6 = 667489211907833441904090408183964916738111 , 123698332225047871848637413013333477895868
m7, v7 = 3567528272153764003837574317682649383619949327607 , 2621823962661199268500092259451160990545103771980

e = 3

mods = [m1, m2, m3, m4, m5, m6, m7]
vals = [v1, v2, v3, v4, v5, v6, v7]

sol = crt(vals, mods)
sol = iroot(sol, 3)
sol = sol[0]
long_to_bytes(int(sol))
```

## PRSA

We are given a sage script in this task:

```python
from sage.all import *
from Crypto.Util.number import bytes_to_long, getPrime

import random
import time
random.seed(time.time())

message = b'flag{REDACTED}' ## the flag has been removed
F.<x> = PolynomialRing(GF(2), x)

p, q = [F.irreducible_element(random.randint(2 ** 10, 2 ** 12)) for _ in range(2)]
R.<y> = F.quotient_ring(p * q)

n = sum(int(bit) * y ** (len(bin(bytes_to_long(message))[2:]) - 1 - i) for i, bit in enumerate(bin(bytes_to_long(message))[2:]))

e = 2 ** 256
c = n ** e 

print(e) ## to be given to the user
print(c) ## to be given to the user
print(p * q) ## to be given to the user
```

Seems very scary: polynomials :( But do remember that factorization of a polynomial is much simpler than factorizing a number $n = p * q$. What happens here is that, 2 polynomails $p, q$ are generated. The flag is converted into a binary stream. And based on that, a polynomail is built. That polynomial is encrypted using $e = 2^{256}$ and $n=p*q$. 

My idea was to take square root (`quadratic residue`) of the encrypted polynomial a 256 times to get the original polynomial. But to do that, we need to do that individually mod $p$ and mod $q$ and then combine the roots via `CRT`. Taking the quadratic residue is easy as there are built in functions in sagemath.

```python
p, q = factor(n)
p, q = p[0], q[0]
p, q

Rp.<Y> = GF(2^p.degree(), modulus = p)
poly1 = Rp(c)
r1 = poly1
for _ in range(256):
    r1 = r1.sqrt()

print(r1)

Rq.<Y> = GF(2^q.degree(), modulus = q)
poly2 = Rq(c)
r2 = poly2
for _ in range(256):
    r2 = r2.sqrt()

print(r2)

res = [r1, r2]
mod = [p, q]
sol = crt(res, mod)

from Crypto.Util.number import long_to_bytes

coeff = [str(i) for i in sol.list()]
msg = int(''.join(coeff[::-1]), 2)
long_to_bytes(msg)
```


## Knapsack

Just from the name one can understand what the solution is. The given script is:

```python
import random
import hashlib
from Crypto.Util.number import bytes_to_long
from Crypto.Cipher import AES

flag = b"The flag has been REDACTED"
secret = b"The seccret has been REDACTED"
key = hashlib.sha256(secret).digest()[:16]

cipher = AES.new(key, AES.MODE_ECB)
padded_flag = flag + b'\x00'*(-len(flag)%16)

ciphertext = cipher.encrypt(padded_flag)

f = open('output.txt','w')
f.write(f"Ciphertext: {ciphertext.hex()}\n\n")

arr = [ random.randint(1,1000000000000) for i in range(40) ]
k = bytes_to_long(secret)
s = 0
for i in range(40):
    if k&(1<<i):
        s+=arr[i]

f.write(f'numbers: {str(arr)[1:-1]}\nsum: {s}\n')
f.close()
```

The challenge is to figure out the secret. In order to recover the secret, we need to find a subset from the set $arr$ who sum $sum$  is given to us. This is a classic subset-sum problem, which can be solved using `meet-in-the-middle` technique. I have already explained this [here](https://tsumiiiiiiii.github.io/fh_crypto/#primes-festival). 

The abridged idea is this:

1. Split the set $arr$ into 2 sets $s_1$, $s_2$. Each has a lenght of 20.
2. Brute force all possible sets of $s_1$ using bitmasks, and for each set, store the subsequent bitmask and sum in a dictionary. 
3. Now brute force all the possible sets of $s_2$ and calculate $need = sum - currentsum$. If need is present in the first dictionary, we know we have found the relevant masks to build our secret.  
4. Append the masks together to get the secret. 

```python
secrets = [...]

s1, s2 = secrets[:20], secrets[20:]

mp1 = dict()
for mask in range(1<<20):
    sm = 0
    for i in range(20):
        if mask & (1<<i):
            sm += s1[i]
    mp1[sm] = mask
    
sum = 7929089016814

for mask in range(1<<20):
    sm = 0
    for i in range(20):
        if mask & (1<<i):
            sm += s2[i]
    need = sum - sm
    if need in mp1:
        print(mp1[need]) #num1
        print(mask) #num2
        
num1 = 283444
num2 = 399173
sec = (num2 << 20) + num1
secret = '1000101001100110100' + '1100001011101000101' # bin(num1) + bin(num2)
secret = long_to_bytes(sec)
secret

ct = 'af95a58f4fbab33cd98f2bfcdcd19a101c04232ac6e8f7e9b705b942be9707b66ac0e62ed38f14046d1cd86b133ebda9'
ct = bytes.fromhex(ct)

from Crypto.Cipher import AES
import hashlib

key = hashlib.sha256(secret).digest()[:16]
cipher = AES.new(key, AES.MODE_ECB)
cipher.decrypt(ct)
```


## Curvy curves

Elliptic curves! Scary stuffs huh? 

```python
from Crypto.Util.number import getRandomNBitInteger, bytes_to_long, long_to_bytes
from sage.all import *

# non-residue
D = 136449572493235894105040063345648963382768741227829225155873529439788000141924302071247144068377223170502438469323595278711906213653227972959011573520003821372215616761555719247287249928879121278574549473346526897917771460153933981713383608662604675157541813068900456012262173614716378648849079776150946352466

# redacted
p = "REDACTED" 
q = "REDACTED"

# n = p*q
n = 22409692526386997228129877156813506752754387447752717527887987964559571432427892983480051412477389130668335262274931995291504411262883294295070539542625671556700675266826067588284189832712291138415510613208544808040871773692292843299067831286462494693987261585149330989738677007709580904907799587705949221601393

flag = b"flag{REDACTED}"

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    def __add__(self, other):
        x = (self.x*other.x + D*self.y*other.y)%n
        y = (self.y*other.x + self.x*other.y)%n
        return Point(x, y)
    def __mul__(self, d):
        Q = Point(1, 0)
        P = Point(self.x, self.y)
        while d != 0:
            if d&1 == 1:
                Q += P
            P += P
            d >>= 1
        return Q
    def __str__(self) -> str:
        return f"{self.x}, {self.y}"

def check_residue(y):
    if pow(y, (p - 1)//2, p) == 1 and pow(y, (q - 1)//2, q) == 1:
        return True
    return False

def gen_point():
    while True:
        x = getRandomNBitInteger(1023 - 240)
        x = bytes_to_long(flag + long_to_bytes(x))
        x %= n
        y2 = ((x*x - 1)*pow(D, -1, n))%n
        if(check_residue(y2)):
            yp = pow(y2, (p + 1) // 4, p)
            yq = pow(y2, (q + 1) // 4, q)
            y = crt([yp, yq], [p, q])
            return Point(x, y)

M = gen_point()
e = 65537
C = M*e
print(C)
# Cx = 10800064805285540717966506671755608695842888167470823375167618999987859282439818341340065691157186820773262778917703163576074192246707402694994764789796637450974439232033955461105503709247073521710698748730331929281150539060841390912041191898310821665024428887410019391364779755961320507576829130434805472435025, Cy = 2768587745458504508888671295007858261576650648888677215556202595582810243646501012099700700934297424175692110043143649129142339125437893189997882008360626232164112542648695106763870768328088062485508904856696799117514392142656010321241751972060171400632856162388575536779942744760787860721273632723718380811912
```

The intended solution was to use the `p + 1` factorization technique. But surprisingly, the factorization was found on `factor-db`.  Once the factorization is found, we can calculate 

$$ phi = (p-1)*(q-1) $$

$$ d = e^{-1} \mod phi $$

Then, $M = C*d$. 

```python
from Crypto.Util.number import getRandomNBitInteger, bytes_to_long, long_to_bytes, getPrime

# non-residue
D = 136449572493235894105040063345648963382768741227829225155873529439788000141924302071247144068377223170502438469323595278711906213653227972959011573520003821372215616761555719247287249928879121278574549473346526897917771460153933981713383608662604675157541813068900456012262173614716378648849079776150946352466

# redacted

p = 12591011258095671596958186047778684066366433713000083733603008978332296147605042520140224748454073644398378458146875090686440895644260506565719708746960331
n = 22409692526386997228129877156813506752754387447752717527887987964559571432427892983480051412477389130668335262274931995291504411262883294295070539542625671556700675266826067588284189832712291138415510613208544808040871773692292843299067831286462494693987261585149330989738677007709580904907799587705949221601393

assert(n % p == 0)
q = n // p

order = (p + 1) * (q + 1)

flag = b"flag{REDACTED}"

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y
    def __add__(self, other):
        x = (self.x*other.x + D*self.y*other.y)%n
        y = (self.y*other.x + self.x*other.y)%n
        return Point(x, y)
    def __mul__(self, d):
        Q = Point(1, 0)
        P = Point(self.x, self.y)
        #print(Q)
        while d != 0:
            if d&1 == 1:
                Q += P
            #print(Q)
            P += P
            d >>= 1
        return Q
    def __str__(self) -> str:
        return f"{self.x}, {self.y}"

def check_residue(y):
    if pow(y, (p - 1)//2, p) == 1 and pow(y, (q - 1)//2, q) == 1:
        return True
    return False

def gen_point():
    while True:
        x = getRandomNBitInteger(1023)
        #x = bytes_to_long(flag + long_to_bytes(x))
        x %= n
        y2 = ((x*x - 1)*pow(D, -1, n))%n
        if(check_residue(y2)):
            yp = pow(y2, (p + 1) // 4, p)
            yq = pow(y2, (q + 1) // 4, q)
            y = crt([yp, yq], [p, q])
            return Point(x, y)


e = 65537
Cx = 10800064805285540717966506671755608695842888167470823375167618999987859282439818341340065691157186820773262778917703163576074192246707402694994764789796637450974439232033955461105503709247073521710698748730331929281150539060841390912041191898310821665024428887410019391364779755961320507576829130434805472435025
Cy = 2768587745458504508888671295007858261576650648888677215556202595582810243646501012099700700934297424175692110043143649129142339125437893189997882008360626232164112542648695106763870768328088062485508904856696799117514392142656010321241751972060171400632856162388575536779942744760787860721273632723718380811912
C = Point(Cx, Cy)

d = int(pow(e, -1, order))

M = C*d
x = M.x
long_to_bytes(x)
# flag{pHUCk_150M0rPh15m_1n70_p2}
```


## Safe curvy curves

Since the previous chall was spoiled due to `factor-db`, this was released as a revenge challenge to force do the intended way. But funnily enough, someone spoiled the factorization of $n$ in `factor-db` too :3 This made the solution just copy paste of previous one. 

