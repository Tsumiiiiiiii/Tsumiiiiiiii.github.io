---
weight: 1
title: "BlackHat MEA 2024 Quals - Trypanophobia and Cheeky  writeup"
date: 2024-09-02T22:30:00+06:00
lastmod: 2024-09-02T22:30:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for  Trypanophobia and Cheeky from BlackHat MEA 24 Quals."

tags: ["crypto", "BlackHatMEA", "RSA", "math", "nth-roots", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true

---

Writeup for  Trypanophobia and Cheeky from BlackHat MEA 24 Quals.


<!--more-->


## Trypanophobia

This was an interactive challenge where the server code is as follows:


```python
#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Qualifiers
#
# [Easy] Crypto - Trypanophobia
#

# Native imports
import os, json, hashlib

# Non-native imports
from Crypto.Util.number import getPrime, isPrime, inverse, GCD     # pip install pycryptodome

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{506f6c796d65726f5761734865726521}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Functions & Classes
class RSAKey:
    def __init__(self):
        self.public = None
        self.private = None
        
    @staticmethod
    def new():
        p = getPrime(1024)
        while True:
            q = getPrime(1024)
            f = (p - 1) * (q - 1)
            if GCD(f, 0x10001) == 1:
                break
        key = RSAKey()
        key.public = {
            'e' : 0x10001
        }
        key.private = {
            'p' : [p, q]
        }
        key.update()
        return key
    
    def update(self):
        self.public['n'] = 1
        self.private['f'] = 1
        for p in self.private['p']:
            self.public['n'] *= p
            self.private['f'] *= (p - 1)
        self.private['d'] = inverse(self.public['e'], self.private['f'])

    def pad(self, x):
        y = int(hashlib.sha256(str(set(self.private['p'])).encode()).hexdigest(), 16)
        while x < self.public['n']:
            x *= y
        x //= y
        return x
        
    def encrypt(self, x):
        if 0 < x < self.public['n']:
            return pow(self.pad(x), self.public['e'], self.public['n'])
        else:
            return 0


# Challenge set-up
HDR = """|
|  ┏┳┓              ┓   ┓ •
|   ┃ ┏┓┓┏┏┓┏┓┏┓┏┓┏┓┣┓┏┓┣┓┓┏┓
|   ┻ ┛ ┗┫┣┛┗┻┛┗┗┛┣┛┛┗┗┛┗┛┗┗┻
|        ┛┛       ┛"""
print(HDR)

ourKey = RSAKey.new()


# Server loop
TUI = "|\n|  Menu:\n|    [A]dd a key\n|    [E]ncrypt flag\n|    [Q]uit\n|"

while True:
    try:

        print(TUI)
        choice = input("|  > ").lower()

        if choice == 'q':
            print('|\n|  [~] Goodbye ~ !\n|')
            break
        
        elif choice == 'a':
            uin = json.loads(input("|  > (JSON) "))
            assert uin.keys() == {'p', 'q'}
            if all([
                isPrime(uin['p']), isPrime(uin['q']),
                len(bin(uin['p'])) == 1024 + 2,
                len(bin(uin['q'])) == 1024 + 2
            ]):
                ourKey.private['p'] += [uin['p'], uin['q']]
                ourKey.update()
            else:
                print('|  [!] Invalid primes.')

        elif choice == 'e':
            enc = ourKey.encrypt(int.from_bytes(FLAG, 'big'))
            print('|  Flag = 0x{:x}'.format(enc))

        else:
            print('|  [!] Invalid choice.')

    except KeyboardInterrupt:
        print('\n|\n|  [~] Goodbye ~ !\n|')
        break

    except Exception as e:
        print('|  [!] ERROR :: {}'.format(e))
```

What happens here is:

1. The server generates two primes both $1024$ bits. Then it *updates* the state where the public key ($n$) and ϕ ($f$) is calculated. $n = \prod_{i=1}^{n} p_i$ and $f = \prod_{i=1}^{n}(p_i - 1)$. **Nor the public key, neither the ϕ is ever revealed to the players**. 
2. We can interact with the server in $2$ ways ($3$ actually but who cares about *quit*). 
3. The first one is to add two keys to the already existing public keys with the condition being both of them should be $1024$ bits each. The `RSA` parameters are recalculated using the process mentioned in the previous step via the *update* function and the 2 new keys are added to the pool of primes.
4. The second type of query is to *encrypt* the `FLAG` with the current public key. It takes help of another function called *pad*. 

### Taking a closer look at the $pad$ function

The original message to be encrypted ($x$) is repeatedly multiplied by some hash value called $y$ until it becomes greater than the current public key ($n$). This can be mathematically represented as follows: $\text{pad(x)} = xy^k$ such that $\text{pad(x)} < n$ and $k$ is unknown (but can be somewhat guessed as we will see soon). 

But how is $y$ calculated? It is simply the $\text{SHA256}$ hash of the pool of primes (which is a list). There is a catch though, it doesn't take the list, rather, the **set of the list**, which is going to be the pivotal point of our exploitation. 

It's easy to see that $y$ is going to be of $256$ bits always as $\text{SHA256}$ hashes are of $32$ bytes.  

### Solution

We will take advantage of the **set** as mentioned before. Notice what happens if we add signatures multiple times with a constant prime $p$. Consider that the initial unknown public key was $n$ and the initial prime pool was $[P, Q]$. If we try to encrypt the `FLAG` now, we will get an unknown pad with an unknown $\text{pad(x)} = x\*y_{0}^k$. The $k$ value is within a specific range depending on the `FLAG` length, but it is generally within $5 \approx 20$. 

#### Add key with $uin[p] = uin[q] = p$ and *encrypt* `FLAG`

Notice that the prime pool is now $[P, Q, p, p]$ and it's set is $(P, Q, p)$. That means, $y_1 = \text{SHA256}((P, Q, p))$.  Also, $\text{pad(x)} = x\*y\_{1}^{k+8}$. The encrypted flag will be $E_1 = (x\*y\_{1}^{k+8})^e \mod (np^2)$ since public key is $n\*p^2$. 

Now why the exponent of $y_1$ is $8$ more than the last is intuitive. See that when we add two primes of $1024$ bits to the pool, the length of the public key increase by $2048$ bits. How many times *more* can we multiply $y_1$ (which is of $256$ bits) because of this increment? $\frac{2048}{256} = 8$ times and hence we can see the $8$ in the exponent. 

#### Add key again with $uin[p] = uin[q] = p$ and *encrypt* `FLAG`

The prime pool becomes $[P, Q, p, p, p, p]$. But the set? It's the same as before $(P, Q, p)$. And since $y$ depends solely on this particular set, we can say that $y_2 = y_1 =\text{SHA256}((P, Q, p))$. We have managed to fix the $y$. Now  $\text{pad(x)} = x\*y_{1}^{k+16}$. The encrypted flag will be $E_2 = (x\*y_{1}^{k+16})^e \mod (np^4)$ since public key is $n*p^4$. 

#### Lining up the equations

We have $E_1 = (x\*y_{1}^{k+8})^e \mod (np^2)$ and $E_2 = (x\*y_{1}^{k+16})^e \mod (np^4)$. We need to remove the $e$ from the exponent somehow. That's basic RSA decryption. But wait, we don't even know the whole public key ($n$ is unknown).  That's not a problem since we know the partial public key($p^2$ and $p^4$ since $p$ was provided by us to begin with). We can reduce the problem to

$$
\begin{aligned}
&E_{1}' &\equiv E_{1} &\equiv (x\*y_{1}^{k+8})^e &\mod p \\\ 
&E_{2}' &\equiv E_{2} &\equiv (x\*y_{1}^{k+16})^e &\mod p 
\end{aligned}
$$

We can now decrypt both $E_{1}'$ and $E_{2}'$ using $ϕ=p-1$ to get

$$
\begin{aligned}
&M_{1} &\equiv x\*y_{1}^{k+8} &\mod p \\\ 
&M_{2} &\equiv x\*y_{1}^{k+16} &\mod p 
\end{aligned}
$$

This lets us do $M_{2} / M_{1}$ to get $c = y_{1}^{8} \mod p$, where $c$ is known. We have to find $y_1$. Doing so is easy as there are built in methods in `sage`. 

```python
F = GF(p)
R.<x> = PolynomialRing(F)
polynomial = x^8 - c
y = polynomial.roots()[1][0] #Takes around 7 minutes on my potato

assert y^8 == c
```

Once we get $y_1$, we can get $x = \frac{M_1}{y_{1}^{k+8}} \mod p$. But we don't know $k$. Remember that I mentioned $k$ can be brute-forced as it's in the range of $5 \approx 20$. So we try all values of $k$ and see which yields the correct `FLAG`.

```python
for k in range(5, 20):
	x = M1 * pow(y, -(k+8), p) % p
	print(long_to_bytes(x))
```

---

## Cheeky

The server side code is below:

```python
#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Qualifiers
#
# [Medium] Crypto - Cheeky
#

# Native imports
import os, time, json
from hashlib import sha256

# Non-native imports
from Crypto.Cipher import AES

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{506f6c79-6d65726f-57617348-65726521}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Functions & Classes
class Database:
    def __init__(self, passkey: bytes):
        if isinstance(passkey, str):
            passkey = passkey.encode()
        self.key = sha256(b"::".join([b"KEY(_FLAG)", passkey, len(passkey).to_bytes(2, 'big')])).digest()
        self.uiv = int(sha256(b"::".join([b"UIV(_KEY)", self.key, len(self.key).to_bytes(2, 'big')])).hexdigest()[:24], 16)
        self.edb = {}

    def _GetUIV(self, f: str, l: int, t: int = 0) -> bytes:
        if not (0 < t < int(time.time())):
            t = int(time.time()); time.sleep(2)
        u = (self.uiv + t).to_bytes(12, 'big')
        v = sha256(b"::".join([b"UIV(_FILE)", f.encode(), l.to_bytes(2, 'big')])).digest()
        return t, bytes([i^j for i,j in zip(u, v)])

    def _Encrypt(self, f: str, x: bytes) -> bytes:
        if isinstance(x, str):
            x = x.encode()
        t, uiv = self._GetUIV(f, len(x))
        aes = AES.new(self.key, AES.MODE_CTR, nonce=uiv)
        return t.to_bytes(4, 'big') + aes.encrypt(x)
    
    def _Decrypt(self, f: str, x: bytes) -> bytes:
        t, x = int.from_bytes(x[:4], 'big'), x[4:]
        _, uiv = self._GetUIV(f, len(x), t=t)
        aes = AES.new(self.key, AES.MODE_CTR, nonce=uiv)
        return aes.decrypt(x)
    
    def Insert(self, f, i, j):
        if isinstance(j, str):
            j = j.encode()
        if isinstance(j, int):
            j = j.to_bytes(-(-len(bin(j)[:2])//8), 'big')
        if f in self.edb:
            x = self._Decrypt(f, self.edb[f])
        else:
            x = b""
        y = x[:i] + j + x[i:]
        z = self._Encrypt(f, y)
        self.edb[f] = z
        return z
    
    def Delete(self, f, i, j):
        if f not in self.edb:
            return b""
        x = self._Decrypt(f, self.edb[f])
        y = x[:i] + x[i+j:]
        z = self._Encrypt(f, y)
        self.edb[f] = z
        return z


# Challenge set-up
HDR = """|
|   __________                __
|  |   _      |--.-----.-----|  |--.--.--.
|  |   |            -__   -__     <   |  |
|  |   |______|_________________|______  |
|  |   |   |                       |_____|
|  |       |
|  `-------'"""
print(HDR)

database = Database(FLAG)
database.Insert('flag', 0, FLAG)


# Server loop
TUI = "|\n|  Menu:\n|    [I]nsert\n|    [D]elete\n|    [Q]uit\n|"

while True:
    try:

        print(TUI)
        choice = input("|  > ").lower()

        if choice == 'q':
            raise KeyboardInterrupt

        elif choice == 'i':
            uin = json.loads(input("|  > (JSON) "))
            assert uin.keys() == {'f', 'i', 'j'}
            ret = database.Insert(uin['f'], uin['i'], uin['j'])
            print("|  '{}' updated to 0x{}".format(uin['f'], ret.hex()))

        elif choice == 'd':
            uin = json.loads(input("|  > (JSON) "))
            assert uin.keys() == {'f', 'i', 'j'}
            ret = database.Delete(uin['f'], uin['i'], uin['j'])
            print("|  '{}' updated to 0x{}".format(uin['f'], ret.hex()))

        else:
            print('|  [!] Invalid choice.')

    except KeyboardInterrupt:
        print('\n|\n|  [~] Goodbye ~ !\n|')
        break

    except Exception as e:
        print('|  [!] ERROR :: {}'.format(e))
```

It looks scary at first sight, but the solution is rather simple. First, we need to understand what is happening in the code. In simple terms, the code implements a "database" where "files"(which are actually strings) can be added or removed. There are two types of queries to communicate with the server:

1. `Insert`: Insert a string at any location in between another string.
2. `Delete`: Delete a substring from another string. 

### Trying to understand the problem

One thing to understand first is that how the database "stores" each "file". It works in a "hashmap" style, where there ia a "key" for each file. Key in a sense that it works as the "primary key" or the identifier or the alias of a file. For example, the $FLAG$ itself is stored using the key "flag". Whenver we have to address a file, we address it using it's key.

#### `Insert` query

It takes $3$ parameters: 
* $f$: "key" of the string we are trying to operate on.
* $i$: index of the string where we want to insert our desired string.
* $j$: string that we want to insert.

Suppose we made the query `insert(f, i, j)` and $s := \text{database}[f]$ and $l = \text{sizeof}(s)$. Then,

$$
\text{s}\_{\text{modified}} = \text{s}\_{0} \ \text{s}\_{1} \ \text{s}\_{2}  \cdots \text{s}\_{i - 1} + \ \text{j} \ + \text{s}\_{i} \ \text{s}\_{i + 1}  \cdots  \text{s}\_{l - 2} \ \text{s}\_{l - 1} 
$$

The DB we be modified as $\text{database}[f] := \text{s}_{modified}$. Also if there isn't any "key" in the DB with our given query $f$, it just creates a new entry with $\text{database}[f] := j$. 

#### `Delete` query

Just like before, this also takes $3$ inputs:
* $f$: the "key" of the string we want to modify.
* $i$: starting index of the substring that we want to delete.
* $j$: ending point of the substring that we want to delete.

If we made the query `delete(f, i, j)` and $s := \text{database}[f]$ and $l = \text{sizeof}(s)$. Then,

$$
\text{s}\_{\text{modified}} = \text{s}\_{0} \ \text{s}\_{1} \ \text{s}\_{2}  \cdots \text{s}\_{i - 1}  \ \text{s}\_{i + j - 1} \ \text{s}\_{i + j} \cdots  \text{s}\_{l - 2} \ \text{s}\_{l - 1} 
$$

#### The `Encrypt` and `Decrypt` function

Both the queries explained above makes use of two other functions called `Encrypt` and `Decrypt`. It's nothing but `AES-CTR` mode of encryption with some "sophisticated" method of $IV$ generation. That said method also uses the current `UNIX-time`, preferably to prevent any sort of forgery. 

**The AES encryption as it's key always uses the FLAG itself. This never changes.**

### A primer on `AES-CTR`

#### How it works

We know AES as a block cipher, but `CTR` mode is known as "stream" cipher. It still works on blocks though, but unlike other modes, there is no hard and fast rule to make the plaintext padded to a multiple of block length. It also doesn't "encrypt" the plaintext directly. "encrypt" in a sense that the `AddRoundKey`, `SubBytes` etc operations doesn't happen on the plaintext, rather on something called a "counter". That "encrypted" text is xored with the plaintext to get the resulting ciphertext.

So if we know the traditional mode as $\text{AES-ECB}(x) = \mathcal{E}(x)$, the `CTR` mode will be $\text{AES-CTR}(x) = \mathcal{E}(\text{COUNTER}) \oplus x$. $\mathcal{E}$ is where the well know AES steps `AddRoundKey`, `SubBytes`, `ShiftRows`, `MixColumns` takes place.

How the `COUNTER` is generated is rather interesting. A counter block is the combination of the $iv$ and $counter$. The $iv$ is given by us. $\text{COUNTER-BLOCK} = \text{iv} \ || \ \text{counter}$. Their length is equal to that of a single AES block length(generally $16$). So fi the $iv$ takes $12$ bytes, the counter will take $4$ bytes. The counter value, that takes on the value of $0$ at the first block, increases by $1$ at each block, while $iv$ remains the same. 

Suppose we have $iv := \text{7f} \ \text{03} \ \text{78} \ \text{69} \ \text{a4} \ \text{f8} \ \text{42} \ \text{64} \ \text{aa} \ \text{d8} \ \text{bf} \ \text{c4}$

<div style="display: flex; gap: 10px; margin-bottom: 15px;">
    <div style="text-align: center;">
        <div style="border: 1px solid #555; padding: 5px; white-space: nowrap;">7f 03 ... bf c4 <span style="color: red;"> 00 00 00 00 </span></div>
        <p>Counter Block #0</p>
    </div>
    <div style="text-align: center;">
        <div style="border: 1px solid #555; padding: 5px; white-space: nowrap;">7f 03 ... bf c4 <span style="color: red;"> 00 00 00 01 </span></div>
        <p>Counter Block #1</p>
    </div>
    <p>....</p>
    <div style="text-align: center;">
        <div style="border: 1px solid #555; padding: 5px; white-space: nowrap;">7f 03 ... bf c4 <span style="color: red;"> 00 00 00 18 </span></div>
        <p>Counter Block #25</p>
    </div>
</div>


As we can see, the <span style="color:red;"> counter</span> gradually increases with each block. The entire `AES-CTR` mode of operation has been visualized below, where $CB, P, C$ represents counter block, plaintext block and ciphertext block respectively: \
\
<img src="https://github.com/Tsumiiiiiiii/Tsumiiiiiiii.github.io/blob/main/content/posts/BHMEA24/tikz-1.svg?raw=true" style="width: 100%; height: auto;" />

#### Can this be *hacked*?

Since the problem we are dealing with concerns the CTR mode, it's only natural that we would be looking for any potential vulnerability than this mode can fall a victim to. There is one very well known attack: *nonce reuse attack*. One thing to realize is that if the key and iv remains the same, it's going to produce the same counter-block every time, which would result in the same encrypted xor crib. 

Suppose we have an oracle that can do the `AES-CTR` operation for us. It intially gives us the ciphertext of an unknown $P_{1}$, but we can get the ciphertext of a known string $P_{2}$.

$$
\begin{aligned}
C_{1} &= \mathcal{E}(CB) \oplus P_{1} \\\
C_{2} &= \mathcal{E}(CB) \oplus P_{2} \\\
\Longrightarrow C_{1} \oplus C_{2} &= P_{1} \oplus P_{2} \\\
\Longrightarrow P_{1} &= (C_{1} \oplus C_{2}) \oplus P_{2}
\end{aligned}
$$

And this results us to leak the unknown $P_1$. 

### Solution

As we have seen before, the database stores everything via `AES-CTR` encryption, which is reflected in the `_getUIV` function. This function is reponsible for producing the nonce, which particularly depends on two things:

1. current `UNIX-TIME`
2. length of the string to be encrypted

That is, we can represent the encryption as $\mathcal{E}(T, L)$. If we can somehow manage to keep the above to factors constant, we might be able to exploit the *nonce reuse thing* that I explained in the previous section. 

Also, the key is always same, as the key itself is the flag. Thus, fixing the time and the length would result in producing the same counter-blocks always. 

#### Leaking `FLAG` length

We know that there is already an entry in the database called `"flag" : FLAG`. We will use this entry to get the length. The idea is that we are going to use the `delete` query to delete *nothing* from the FLAG, that is, return the encrypted version of the flag itself.  Since we have already shown that CTR mode of operation gives the same length of encrypted text as the plain text, as padding is not needed. 

But how do we simulate delete *nothing*? Notice the delete functio: `y = x[:i] + x[i+j:]`. That is, it takes the initial `i` bytes, rejects the next `j` bytes and takes the rest. Suppose that the flag is of $50$ bytes and we send $i := 100, j := 0$. The script would *try* to take the initial $100$ bytes of the flag, but since the flag is capped at $50$ bytes, it will take all the $50$ bytes, and since `j` is $0$, it would reject nothing, thus sending us the whole `AES-CTR(FLAG)`. Actually it would send extra 4 bytes, which is the UNIX time. But we can simply reject them and keep the rest. 

Thus the query is `delete("flag", 100, 0)`. 

We get $45$ bytes in return, which means our flag consists of $41$ bytes.

#### How to **fix** the time

We can create two instances at the same time, and make them run parallely. Assume that the instances were created at time $T$. As per the `_getUIV` function, each nonce generation costs $2$ seconds.

**Instance I**:

1. `delete(flag, 41, 100)`: done to kill some time for parallelization.
2. `delete(flag, 41, 100)`: done to get the encryted text: $c_1 = \mathcal{E}(T + 4, 41) \oplus \text{FLAG}$.

**Instance II**:

1. `delete(flag, 0, 41)`: done to delete the flag itself.
2. `insert(flag, 0, 'aa...aa')`: we send $41$ a's to get $c_2 = \mathcal{E}(T + 4, 41) \oplus "aa...aa"$.

This can be visualized as follows: \
\
<img src="https://github.com/Tsumiiiiiiii/Tsumiiiiiiii.github.io/blob/main/content/posts/BHMEA24/tikz_2.svg?raw=true" style="width: 100%; height: auto;" />

#### Finishing off the exploit

Now it's just some simple xors to retrieve the flag.

$$
\begin{aligned}
c_1 \oplus c_2 &= (\mathcal{E}(T + 4, 41) \oplus \text{FLAG}) \oplus (\mathcal{E}(T + 4, 41) \oplus "aa...aa") \\\
               &= \text{FLAG} \oplus "aa...aa" \\\
            \Longrightarrow \text{FLAG} &= (c_1 \oplus c_2) \oplus "aa...aa"
\end{aligned}
$$

The solution script is as follows:

```python
import json
import threading
from Crypto.Util.number import bytes_to_long as b2l


def fun1(results, index):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('54.78.163.105', 32556))
    
    recvuntil(sock, b"|  > ")
    sendline(sock, b"d")
    recvuntil(sock, b") ")
    key = json.dumps(
        {"f" : 'flag', "i" : 41, "j" : 100}
    )
    sendline(sock, str(key).encode())
    stuff = bytes.fromhex(recvline(sock).decode().strip().split('0x')[1])
    
    recvuntil(sock, b"|  > ")
    sendline(sock, b"d")
    recvuntil(sock, b") ")
    key = json.dumps(
        {"f" : 'flag', "i" : 41, "j" : 100}
    )
    sendline(sock, str(key).encode())
    stuff = bytes.fromhex(recvline(sock).decode().strip().split('0x')[1])
    
    results[index] = [b2l(stuff[:4]), stuff[4:]]

def fun2(results,index):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('54.78.163.105', 32556))
    
    recvuntil(sock, b"|  > ")
    sendline(sock, b"d")
    recvuntil(sock, b") ")
    key = json.dumps(
        {"f" : 'flag', "i" : 0, "j" : 41}
    )
    sendline(sock, str(key).encode())
    stuff = bytes.fromhex(recvline(sock).decode().strip().split('0x')[1])
    
    recvuntil(sock, b"|  > ")
    sendline(sock, b"i")
    recvuntil(sock, b") ")
    key = json.dumps(
        {"f" : 'flag', "i" : 0, "j" : 'a' * 41}
    )
    sendline(sock, str(key).encode())
    stuff = bytes.fromhex(recvline(sock).decode().strip().split('0x')[1])
    results[index] = [b2l(stuff[:4]), stuff[4:]]

results = [None, None]

# Running both functions in parallel using threading
thread1 = threading.Thread(target=fun1, args=(results, 0))
thread2 = threading.Thread(target=fun2, args=(results, 1))

# Start both threads
thread1.start()
thread2.start()

# Wait for both threads to complete
thread1.join()
thread2.join()

t0, ct0 = results[0]
t1, ct1 = results[1]

t0, ct0, t1, ct1
```

```python
def xor(sa, sb):
    return bytes([a ^ b for a, b in zip(sa, sb)])

pad = xor(b'a' * 41, ct1)
flag = xor(pad, ct0)
```
