---
weight: 1
title: "pico CTF 2022 - Cryptography Writeups"
date: 2023-06-30T09:20:00+06:00
lastmod: 2023-06-30T09:20:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Short, descriptive write-ups for challenges I did from the competition."

tags: ["crypto", "pico CTF", "english"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---

Short, descriptive write-ups for challenges I did from the competition.

<!--more-->

## Overview

It has been more than 1 year since the competition. But better late than never 👾

I managed to solve all the Cryptography problems (they were very easy). But this had been a very important milestone for me, getting me hooked strongly on this field. 

## basic-mod1

{{< admonition note "Challenge Information" >}}
* **Points:** 100
* **Description:** We found this weird message being passed around on the servers, we think we have a working decryption scheme.
Download the message [here](https://artifacts.picoctf.net/c/127/message.txt).
Take each number mod 37 and map it to the following character set: 0-25 is the alphabet (uppercase), 26-35 are the decimal digits, and 36 is an underscore.
Wrap your decrypted message in the picoCTF flag format (i.e. picoCTF{decrypted_message})

{{< /admonition >}}

 Just do as the instructions say. Mod the serial no. of each character(0 for A, 1 for B,...) by 37 and map the result by the relevant characters(A for 0, B for 1,...)

```python 
c = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_" #all the relevant characters
ct = "128 63 242 87 151 147 50 369 239 248 205 346 299 73 335 189 105 293 37 214 333 137".split()
ans = ""
for m in ct:
    m = int(m)
    ans += c[m % 37]
print("picoCTF{" + ans + "}")
```
> Flag: **picoCTF{R0UND_N_R0UND_CE58A3A0}**

## basic-mod2

{{< admonition note "Challenge Information" >}}
* **Points:** 100
* **Description:** A new modular challenge!
Download the message [here](https://artifacts.picoctf.net/c/178/message.txt).
Take each number mod 41 and find the modular inverse for the result. Then map to the following character set: 1-26 are the alphabet, 27-36 are the decimal digits, and 37 is an underscore.
Wrap your decrypted message in the picoCTF flag format (i.e. picoCTF{decrypted_message})

{{< /admonition >}}

Very similar to the first problem, except that we have to find the modular inverse. In python you can do it like this `pow(n, -1, 41)`
```python
c = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
ct = "186 249 356 395 303 337 190 393 146 174 446 127 385 400 420 226 76 294 144 90 291 445 137".split()
ans = ""
for m in ct:
    m = pow(int(m), -1, 41)
    ans += c[m - 1]
print("picoCTF{" + ans + "}")
```
> Flag: **picoCTF{1NV3R53LY_H4RD_B7FB947C}** 

## credstuff

{{< admonition note "Challenge Information" >}}
* **Points:** 100
* **Description:** We found a leak of a blackmarket website's login credentials. Can you find the password of the user cultiris and successfully decrypt it?
Download the leak [here](https://artifacts.picoctf.net/c/151/leak.tar).
The first user in usernames.txt corresponds to the first password in passwords.txt. The second user corresponds to the second password, and so on.
{{< /admonition >}}

We copy-paste the contents of `usernames.txt` in a code editor and search for the username **cultiris** and find that it is in line no. 378. Now that we know this information, we can say that the 378th line of `passwords.txt` will contain the password for that particular user.  
The password is : `cvpbPGS{P7e1S_54I35_71Z3}`  
It is giving us an instant ROT cipher vibe. Trying ROT 13 indeed reveals the flag.  
  
> Flag: **picoCTF{C7r1F_54V35_71M3}**

## morse-code

{{< admonition note "Challenge Information" >}}
* **Points:** 100
* **Description:** Morse code is well known. Can you decrypt this?
Download the file [here](https://artifacts.picoctf.net/c/79/morse_chal.wav).
Wrap your answer with picoCTF{}, put underscores in place of pauses, and use all lowercase.
{{< /admonition >}}

> Flag: **picoCTF{WH47_H47H_90D_W20U9H7}**

## rail-fence

{{< admonition note "Challenge Information" >}}
* **Points:** 100
* **Description:** A type of transposition cipher is the rail fence cipher, which is described [here](https://en.wikipedia.org/wiki/Rail_fence_cipher). Here is one such cipher encrypted using the rail fence with 4 rails. Can you decrypt it?
Download the message [here](https://artifacts.picoctf.net/c/190/message.txt).
Put the decoded message in the picoCTF flag format, picoCTF{decoded_message}.
{{< /admonition >}}

Classic rail fence cipher.  
Using an online decrypter like [this](https://www.boxentriq.com/code-breaking/rail-fence-cipher) and setting the `Rails` to 4 reveals the secret to be `The flag is: WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_83F6D8D7`.  
  
> Flag: **picoCTF{WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_83F6D8D7}**

## substitution0

{{< admonition note "Challenge Information" >}}
* **Points:** 100
* **Description:** A message has come in but it seems to be all scrambled. Luckily it seems to have the key at the beginning. Can you crack this substitution cipher?
Download the message [here](https://artifacts.picoctf.net/c/153/message.txt).
{{< /admonition >}}

[This](https://www.guballa.de/substitution-solver) particular website is always my first choice for problems related to substitution cipher.  
  
> Flag: **picoCTF{5UB5717U710N_3V0LU710N_03055505}**

## substitution1

{{< admonition note "Challenge Information" >}}
* **Points:** 100
* **Description:** A second message has come in the mail, and it seems almost identical to the first one. Maybe the same thing will work again.
Download the message [here](https://artifacts.picoctf.net/c/181/message.txt).
{{< /admonition >}}

The same approach is followed once again. There is a single catch here though. We get `picoCTF{FR3JU3NCY_4774CK5_4R3_C001_7AA384BC}` but the part `FR3JU3NCY` doesn't make any sense. We changed it to `FR3QU3NCY1` and voila!  
  
> Flag: **picoCTF{FR3JU3NCY_4774CK5_4R3_C001_7AA384BC}**

## substitution2

{{< admonition note "Challenge Information" >}}
* **Points:** 100
* **Description:** It seems that another encrypted message has been intercepted. The encryptor seems to have learned their lesson though and now there isn't any punctuation! Can you still crack the cipher?
Download the message [here](https://artifacts.picoctf.net/c/112/message.txt).
{{< /admonition >}}

Same as before, and with no catches. 
  
> Flag: **picoCTF{N6R4M_4N41Y515_15_73D10U5_702F03FC}**

## transposition-trial

{{< admonition note "Challenge Information" >}}
* **Points:** 100
* **Description:** Our data got corrupted on the way here. Luckily, nothing got replaced, but every block of 3 got scrambled around! The first word seems to be three letters long, maybe you can use that to recover the rest of the message.
Download the corrupted message [here](https://artifacts.picoctf.net/c/193/message.txt).
{{< /admonition >}}

This is a very classic problem in cryptography.  
As the hint said, we divide the strings in blocks of 3. It can be intuitively said that the first block `heT` will be `The`. From it we guess that the first character is shifted to the second position, second character to the third position and the last character to the first position.  
```python
s = "heTfl g as iicpCTo{7F4NRP051N5_16_35P3X51N3_VE1A1D3D}B"
ans = ""
cur = []
for i in range(len(s)):
    if i % 3 == 0 and i != 0:
        ans += cur[2] + cur[0] + cur[1]
        cur = []
    cur.append(s[i])
ans += cur[2] + cur[0] + cur[1]
print(ans)
```
  
> Flag: **picoCTF{7R4N5P051N6_15_3XP3N51V3_AE131DBD}**

## Vignere

{{< admonition note "Challenge Information" >}}
* **Points:** 100
* **Description:** Can you decrypt this message?
Decrypt this [message](https://artifacts.picoctf.net/c/158/cipher.txt) using this key "CYLAB".
{{< /admonition >}}

Another very classic cipher.  
We plug the ciphertext and the key in [this](https://www.dcode.fr/vigenere-cipher) website and the flag is found. 

> Flag: **picoCTF{D0NT_US3_V1G3N3R3_C1PH3R_d85729g7}**

## Very Smooth

{{< admonition note "Challenge Information" >}}
* **Points:** 300
* **Description:** Forget safe primes... Here, we like to live life dangerously... >:)
Artifacts are [gen.py](https://artifacts.picoctf.net/c/148/gen.py) and [output.txt](https://artifacts.picoctf.net/c/148/output.txt).
{{< /admonition >}}

From the hint and the title we understand this problem is about [pollard p-1 factorization](https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm).  
The algorithm itself is not that difficult to code, or, you can use an already implemented code. After you factor the modulus, everything is trivial from there.
```python
import  math
from Crypto.Util.number import long_to_bytes

def  pollard (n): 
    a = 2 
    b = 2 
    while True : 
        a = pow(a, b , n) 
        d = math.gcd(a - 1, n) 
        if 1 < d < n : return  d 
        b  +=  1


n = 0xc5261293c8f9c420bc5291ac0c14e103944b6621bb2595089f1641d85c4dae589f101e0962fe2b25fcf4186fb259cbd88154b75f327d990a76351a03ac0185af4e1a127b708348db59cd4625b40d4e161d17b8ead6944148e9582985bbc6a7eaf9916cb138706ce293232378ebd8f95c3f4db6c8a77a597974848d695d774efae5bd3b32c64c72bcf19d3b181c2046e194212696ec41f0671314f506c27a2ecfd48313e371b0ae731026d6951f6e39dc6592ebd1e60b845253f8cd6b0497f0139e8a16d9e5c446e4a33811f3e8a918c6cd917ca83408b323ce299d1ea9f7e7e1408e724679725688c92ca96b84b0c94ce717a54c470d035764bc0b92f404f1f5
c = 0x1f511af6dd19a480eb16415a54c122d7485de4d933e0aeee6e9b5598a8e338c2b29583aee80c241116bc949980e1310649216c4afa97c212fb3eba87d2b3a428c4cc145136eff7b902c508cb871dcd326332d75b6176a5a551840ba3c76cf4ad6e3fdbba0d031159ef60b59a1c6f4d87d90623e5fe140b9f56a2ebc4c87ee7b708f188742732ff2c09b175f4703960f2c29abccf428b3326d0bd3d737343e699a788398e1a623a8bd13828ef5483c82e19f31dca2a7effe5b1f8dc8a81a5ce873a082016b1f510f712ae2fa58ecdd49ab3a489c8a86e2bb088a85262d791af313b0383a56f14ddbb85cb89fb31f863923377771d3e73788560c9ced7b188ba97
e = 0x10001

p = pollard(n)
q = n // p
assert(p * q == n)
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```

> Flag: **picoCTF{7c8625a1}**

## Sequences

{{< admonition note "Challenge Information" >}}
* **Points:** 400
* **Description:** I wrote this linear recurrence function, can you figure out how to make it run fast enough and get the flag?
Download the code here [sequences.py](https://artifacts.picoctf.net/c/66/sequences.py)
Note that even an efficient solution might take several seconds to run. If your solution is taking several minutes, then you may need to reconsider your approach.
{{< /admonition >}}

Matrix diagonalization problem. Any recurrence relation can be expressed using matrixes, from which, we can calculate the `n-th term` in the sequence very efficiently.
```python
import math
import hashlib
import sys
#from tqdm import tqdm
import functools
from numpy.core.numerictypes import issubdtype
from numpy.core.numeric import concatenate, isscalar, binary_repr, identity, asanyarray, dot
import numpy as np

A = np.array([[21, 301, -9549, 55692], [1, 0, 0, 0],
              [0, 1, 0, 0], [0, 0, 1, 0]], dtype=np.int64)
k = int(2e7)
F = np.array([[4], [3], [2], [1]], dtype=np.int64)

mod = 10**10000

ITERS = int(2e7)
VERIF_KEY = "96cc5f3b460732b442814fd33cf8537c"
ENCRYPTED_FLAG = bytes.fromhex(
    "42cbbce1487b443de1acf4834baed794f4bbd0dfe08b5f3b248ef7c32b")

# This will overflow the stack, it will need to be significantly optimized in order to get the answer :)

#@functools.cache


def m_func(i):
    if i == 0:
        return 1
    if i == 1:
        return 2
    if i == 2:
        return 3
    if i == 3:
        return 4

    return 55692*m_func(i-4) - 9549*m_func(i-3) + 301*m_func(i-2) + 21*m_func(i-1)

# Decrypt the flag


def decrypt_flag(sol):
    sol = sol % (10**10000)
    sol = str(sol)
    sol_md5 = hashlib.md5(sol.encode()).hexdigest()

    if sol_md5 != VERIF_KEY:
        print("Incorrect solution")
        return
        #sys.exit(1)

    key = hashlib.sha256(sol.encode()).digest()
    flag = bytearray([char ^ key[i]
                      for i, char in enumerate(ENCRYPTED_FLAG)]).decode()

    return flag


def matrix_power(M, n, mod_val):
    # Implementation shadows numpy's matrix_power, but with modulo included
    M = asanyarray(M)
    if len(M.shape) != 2 or M.shape[0] != M.shape[1]:
        raise ValueError("input  must be a square array")
    if not issubdtype(type(n), int):
        raise TypeError("exponent must be an integer")

    from numpy.linalg import inv

    if n == 0:
        M = M.copy()
        M[:] = identity(M.shape[0])
        return M
    elif n < 0:
        M = inv(M)
        n *= -1

    result = M % mod_val
    if n <= 3:
        for _ in range(n-1):
            result = dot(result, M) % mod_val
        return result

    # binary decompositon to reduce the number of matrix
    # multiplications for n > 3
    beta = binary_repr(n)
    Z, q, t = M, 0, len(beta)
    while beta[t-q-1] == '0':
        Z = dot(Z, Z) % mod_val
        q += 1
    result = Z
    for k in range(q+1, t):
        Z = dot(Z, Z) % mod_val
        if beta[t-k-1] == '1':
            result = dot(result, Z) % mod_val
    return result % mod_val


if __name__ == "__main__":
    X = matrix_power(A, k - 1, mod)
    R = X.dot(F)
    for i in range(len(R)):
        sol = R[i, 0]
        m = decrypt_flag(sol)
        if m is not None and 'picoCTF' in m:
            print(m)
            break
```

> Flag: **picoCTF{b1g_numb3rs_4ebc92cc}**

## Sum-O-Primes

{{< admonition note "Challenge Information" >}}
* **Points:** 400
* **Description:** We have so much faith in RSA we give you not just the product of the primes, but their sum as well!
  Artifacts are [gen.py](https://artifacts.picoctf.net/c/98/gen.py) and [output.txt](https://artifacts.picoctf.net/c/98/output.txt)
{{< /admonition >}}

Simple RSA problem.  
We are given the sum and product of the two primes. Figuring out the two primes from that is trivial algebra. 
One thing to be cautious about is that the `sqrt` function loses precision for huge integers. Use `isqrt` function from the same `math` module. 
```python
from math import isqrt
from Crypto.Util.number import long_to_bytes

x = 0x1603fc8d929cb31edf62bcce2d06794f3efd095accb163e6f2b78941bd8c646d746369636a582aaac77c16a9486881a9e3db26d742e48c4adcc417ef98f310a0c5433ab077dd872530c3c3c77fe0c080d84154bfdb4c920df9617e986999104d9284516c7babc80dc53718d59032aefdf41b9be53957dea3f00a386b2666d446e
n = 0x75302ba292dc4bf47ffd690b8edc70ef1fcca5e148b2b9c1b60227788afcfe77a0097929ed3789fe51ac66f678c558244890a09ae4af3e7d098fd366a1c859edabbff1c9e164d5354968798107ae8518fcaab3743de58a141ffd26c1e16cb09fed1f6b0d68536ec7fba744ed120fea8c3a7ac1ebfa55d664d2f321fb44e814650147a9031f3bfa8f69d87393c7d88976d28d147398a355020bcb8e5613f0b29028b77db710e163ca1019fd3c3a065465ea457adec45243c385d12d3a1de3178f6ca05964be92e8b5bc24d420956de96ccc9ce39e70705660eb6b2f4e675aac7d6d7ba45c84223fc5819b37aa85beff1382f1c2c3b97603150f30c17f7e674441
c = 0x562888c70ce9a5c5ed9a0be1b6196f854ba2efcdb6dd0f79319ee9e1142659f90a6bae67481eb0f635f445d3c9889da84639beb84ff7159dcf4d3a389873dc90163270d80dbb9503cbc32992cb592069ba5b3eb2bbe410a3121d658f18e100f7bd878a25c27ab8c6c15b690fce1ca43288163c544bfce344bcd089a5f4733acc7dc4b6160718e3c627e81a58f650281413bb5bf7bad5c15b00c5a2ef7dbe7a44cce85ed5b1becd5273a26453cb84d327aa04ad8783f46d22d61b96c501515913ca88937475603437067ce9dc10d68efc3da282cd64acaf8f1368c1c09800cb51f70f784bd0f94e067af541ae8d20ab7bfc5569e1213ccdf69d8a81c4746e90c1
e = 65537

y = isqrt((x * x) - 4 * n)
p, q = (x + y) // 2, (x - y) // 2

assert(p * q == n)

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
```
> Flag: **picoCTF{674b189f}**

## NSA Backdoor

{{< admonition note "Challenge Information" >}}
* **Points:** 500
* **Description:** I heard someone has been sneakily installing backdoors in open-source implementations of Diffie-Hellman... I wonder who it could be... ;)
  Artifacts are [gen.py](https://artifacts.picoctf.net/c/209/gen.py) and [output.txt](https://artifacts.picoctf.net/c/209/output.txt)
{{< /admonition >}}

Discrete logarithm problem.  
[Sage-math](https://www.sagemath.org/) is used for this problem. We find out the p and q using pollard p - 1 factorization. After that, we use find the discrete log modulo p and q respectively. The two solutions are then combined using the **Chinese Remainder Theorem** and flag is found.
```sage
from Crypto.Util.number import long_to_bytes

def  pollard(n): 
    a = 2 
    b = 2 
    while True : 
        a = pow(a, b , n) 
        d = math.gcd(a - 1, n) 
        if 1 < d < n : return  d 
        b  +=  1

n = 0x8d9424ddbf9fff7636d98abc25af7fde87e719dc3ceee86ca441b079e167cc22ff283f1a8671263c2e5ebd383ca3255e903b37ebca9961fd8a657cb987ef1e709866acc457995bfc7a6d4be7e88b9ee03a9872329e05cb7eb849d61e4bb44a25be8bd42f19f13a9417bfab73ba616b7c05865640682dc685890bbce8c20c65175f322b5b27788fede4f6704c6cb7b2d2d9439fad50f8b79ffab0b790591ae7f43bd0316565b097b9361d3beb88b6ef569d05af75d655b5133dc59a24c86d147a5eb5311344a66791f03a3da797effd600aa61564ce4ffd81f70bfedf12ca7857b9ac781a4823f6c1a08f1e86f8fe0e1eb3eb6ac71b63e4b03ba841c8588f6df1
c = 0x4679331be9883c4518d4870352281710777bcd74e6c9e9abb886254cf42c2f7adf5b58af8c8c00a51a72ee1ffaa8af3e9877a11d8ee8702446f1814a0255013a1e1b50a1c795218130a0dade9a5eb6b2c74a726c689ea9a5fe8391d7963d0a648c7ed79f3571d28252fd109f071a3f4ed6cb1de203c24e1cb5517983a8946a4b69cb39844c9f1c6975ad3f9ff7075b1c3a28a8eb25e28d7ecab781686412ca81f0c646094782c8cbacce9a58609c8041b82f9052ff0afd7c9953fa191ed548cf756e7f713341b434b6cc84ac62ff14740c213c60985fc71a6d23ffec7c2e145af0a4217af5f3263083030bc803c0e591a18760c4ea957f72017dcebe7b130e08
p = pollard(n)
q = n // p
assert(p * q == n)
'''
c = 3 ^ g mod n
this is equivalent to
c = 3 ^ g mod p
c = 3 ^ g mod q
and then joining them by chinese remainder theorem
'''
P = GF(p)
x1 = discrete_log(P(c), P(3))
Q = GF(q)
x2 = discrete_log(Q(c), Q(3))
m = crt([x1, x2],[p - 1, q - 1])
print(long_to_bytes(m))
```
> Flag: **picoCTF{99f38837}**
