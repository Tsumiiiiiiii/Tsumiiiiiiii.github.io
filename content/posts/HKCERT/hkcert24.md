---
weight: 1
title: "HKCERT 2024 Quals - Writeups for Pigeon Post(2)"
date: 2024-11-23T22:30:00+06:00
lastmod: 2024-11-23T22:30:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeups for Pigeon Post(2) from HKCERT CTF 24 quals."

tags: ["crypto", "HKCERT", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true

---

Writeups for Pigeon Post(2) from HKCERT CTF 24 quals.
<!--more-->

This is the second problem of the   `Pigeon post` series, and naturally it's difficulty level is much higher compared to its predecessor. This is the script that we are provided with:

```python
import json
import hashlib
import os
import secrets
from Crypto.Cipher import AES
import re

# This is the parameter specified in RFC-3526. Let's assume this is safe :)
# https://datatracker.ietf.org/doc/html/rfc3526#section-3
P = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
G = 0x2

class User:
    def __init__(self, id, secret=None, other_secret=None):
        self.id = id
        self.secret = secret
        self.other_secret = other_secret

        self.private_key = None
        self.session_key = None

        pass

    # Message handler
    def handle_message(self, message):
        message = json.loads(message)
        type_ = message.get('type')
        if type_ == 'init_handshake':
            res = self.init_handshake()
        elif type_ == 'receive_handshake':
            other_public_key = message.get('public_key')
            res = self.receive_handshake(other_public_key)
        elif type_ == 'finish_handshake':
            other_public_key = message.get('public_key')
            res = self.finish_handshake(other_public_key)
        elif type_ == 'communicate':
            ciphertext = bytes.fromhex(message.get('ciphertext'))
            res = self.communicate(ciphertext)
        else:
            raise Exception(f'unknown message type {type_}')

        return json.dumps(res, separators=(',', ':'))

    # ===

    # Phase 1: Handshaking

    def init_handshake(self):
        assert self.private_key is None

        self.private_key = secrets.randbelow(P)
        self.public_key = pow(G, self.private_key, P)
        return {
            "type": "receive_handshake",
            "public_key": self.public_key
        }

    def receive_handshake(self, other_public_key):
        assert self.private_key is None
        assert self.session_key is None

        self.private_key = secrets.randbelow(P)
        self.public_key = pow(G, self.private_key, P)

        self.session_key = derive_session_key(other_public_key, self.private_key)

        return {
            "type": "finish_handshake",
            "public_key": self.public_key
        }

    def finish_handshake(self, other_public_key):
        assert self.session_key is None

        self.session_key = derive_session_key(other_public_key, self.private_key)
        
        message = b'done!'
        ciphertext = encrypt_message(self.session_key, message)

        return {
            "type": "communicate",
            "ciphertext": ciphertext.hex()
        }

    # Phase 2: Encrypted communication

    def communicate(self, incoming_ciphertext):
        incoming_message = decrypt_message(self.session_key, incoming_ciphertext)

        # message handler
        if self.id == 'Byron':
            if incoming_message == b'done!':
                outgoing_message = f'what is the flag? I have the secret {self.secret}'.encode()
            elif incoming_message.startswith(b'the flag is '):
                flag = incoming_message[12:].strip()
                if re.match(br'hkcert24{.*}', flag):
                    outgoing_message = b'nice flag!'
                else:
                    outgoing_message = b'too bad...'
            else:
                outgoing_message = b'???'
        elif self.id == 'Alice':
            if incoming_message == f'what is the flag? I have the secret {self.other_secret}'.encode():
                outgoing_message = f'the flag is {self.secret}'.encode()
            elif incoming_message == b'nice flag!':
                outgoing_message = b':)'
            elif incoming_message == b'too bad...':
                outgoing_message = b'what happened?'
            else:
                outgoing_message = b'???'

        outgoing_ciphertext = encrypt_message(self.session_key, outgoing_message)

        return {
            "type": "communicate",
            "ciphertext": outgoing_ciphertext.hex()
        }

# Utility functions

def derive_session_key(other_public_key, self_private_key):
    shared_key = pow(other_public_key, self_private_key, P)
    session_key = hashlib.sha256(shared_key.to_bytes(512, 'big')).digest()
    return session_key

def encrypt_message(session_key: bytes, message: bytes):
    nonce = os.urandom(8)
    cipher = AES.new(session_key, AES.MODE_CTR, nonce=nonce)
    return nonce + cipher.encrypt(message)

def decrypt_message(session_key: bytes, ciphertext: bytes):
    nonce, ciphertext = ciphertext[:8], ciphertext[8:]
    cipher = AES.new(session_key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ciphertext)


def main():
    flag = os.environ.get('FLAG', 'hkcert24{***REDACTED***}')
    token = os.urandom(8).hex()

    alice = User('Alice', flag, token)
    byron = User('Byron', token)

    res = alice.handle_message('{"type":"init_handshake"}')
    print(res)

    res = byron.handle_message(res)
    print(res)

    res = alice.handle_message(res)
    print(res)

    while True:
        command, *args = input('🕊️  ').strip().split(' ')

        if command == 'alice':
            # send a message to Alice
            content, = args
            print(alice.handle_message(content))

        elif command == 'byron':
            # send a message to Byron
            content, = args
            print(byron.handle_message(content))


if __name__ == '__main__':
    try:
        main()
    except:
        print('😡')
```

## Understanding the given code

In short, it defines a protocol similar to the diffie hellma message exchange  protocol. Apart from some utility functions, which are very easy to understand, most of the "important" stuffs happen in the "User" class. That is where will aim to take a closer look at. A prime and a base ($P, G$) are given.

1. `Initialize` Some secret variables are initialized, and a id variable which stores the name(Alice or Byron). The private keys and session keys are left uninitialized for now. 
2. `handle_message` Works like a "middleman" function - based on the interaction, directs to some other functions as asked.
3. `init_handshake` The private key is randomly sampled below $P$ and from it the public key $pub = G^{pruv} \mod P$.(**Asserts the private key is not already initialized at start**).
4. `receive_handshake` Given that the private key and session key is not already initialized, the private and the public key is initialized as before. Then the session key is found using the `derived_session_key` using other public key(received from another user) and it's own private key.
5. `finish_handshake` With the assertion that the session key is not already initalized, it goes on to derive a session key and encrypts a message "done!" with that session key.
6. `communicate` The user sends an encrypted message. It decrypts that message and based on who the user is (Alice or Byron), it behaves differently.
    - If the user is Byron:
      - If the decrypted message is "done!" it gives the secret.
      - If the message starts with "the flag is ", it checks if the remaining message is of the format `hkcert{.*}`. Based on success or failure, it reprsents with "nice flag!" or "too bad...". **Note that the reponse is first encrypted then returned.**
    - If the user is Alice:
      - If the message contains the secret of the other party(Byron's), it replies with its own secret.
      - If the message is "nice flag!", it replies with ":)", if it was "too bad...", it replies with "what happened?", else it replies with "???". Once again the reply if first encrypted.

There are some utitlity functions as I have previously mentioned:

1. `derive session key`: It calcuates the session key using $\textbf{SHA256}(op^{priv} \ mod P)$ where the $op, priv$ respectively represents other public key and it's own private key. 
2. `encrypt_message`: A random nonce is generated and the message is encrypted with AES-CTR. Both the nonce and ciphertext is returned.
3. `decrypt_message`: It decrypts the given ciphertext from the nonce and returns.

Unlike its predecessor, a lot of operations are already done for us here, if we check the `main` function. They are represented by the sequence diagram - 

{{< mermaid >}}
sequenceDiagram
    participant A as Alice
    participant J as Byron
    A->>J: init handshake
    J->>A: receive handshake
    A->>J: finalize handshake
{{< /mermaid >}}

Then we get unlimited queries of the form - input a name and the type of query that we want to do. Based on that, give us the corresponding output. 

## Exploring viable options

With those steps done for us already, what else can we do using the queries that we can avail?

- [❌] `init_handshake` Because the private key is already initalized.
- [❌] `receive_handshake` The private key and the session key is already initalized.
- [❌] `finish_handshake` The session key is already initalized.
- [✅] `communicate` Can be done without any errors or hindrance.

So all we can do with the unlimited number of queries we have is to call the `communicate` function with the user Alice or Byron. We have to make do with it somehow. 

During the contest I spent a considerable amount of time chasing dead ends. Like my initial idea was to check if the given parameters had a backdoor in it, or maybe the prime had a smooth order? Suffices to say none of those ideas came to fruition. 

## The correct approach

Before we proceed any further, its important to know that the mode of encryption used here is AES-CTR. The internal details of CTR is not necessary, though knowing the basics would do no harm.
I have already written a primer [here](https://tsumiiiiiiii.github.io/bhmea24/#a-primer-on-aes-ctr), in case you want to take a peek. What you should know about CTR mode, however, is that:
1. We don't "encrypt" the plaintext itself per se, rather we encrypt something called the iv and then "xor" it with the plaintext. That is, if we represent the normal encryption as $\mathcal{E}(pt)$, this mode would behave as  $\textbf{AES-CTR}(pt) = \mathcal{E}(iv) \oplus pt$. 
2. Since the plaintext is only used as a xor-pad, there is no relevance of "padding" in this mode. That is why, **The plaintext and the ciphertext has the exact same length in CTR.** Keep that in mind. Infact, you can use this property as a hint to skip ahead and solve the problem yourselves if you so want.

This property of Counter mode lets us retrieve the xor-pad in case the plaintext itself is known. The pad, $\mathcal{E}(iv) = \textbf{AES-CTR}(pt) \oplus pt$. We need this because we plan to leverage this part of the `communicate` function:

```py
            elif incoming_message.startswith(b'the flag is '):
                flag = incoming_message[12:].strip()
                if re.match(br'hkcert24{.*}', flag):
                    outgoing_message = b'nice flag!'
                else:
                    outgoing_message = b'too bad...'
```

We could possibly deploy a strategy to guess the flag by forcing it to match the proper format, but for that we need the corresponding encrypted ciphertext. That is, suppose we wanted to check for the validity of b'the flag is hkcert24{a}", so we would require $\text{AES-CTR}(\text{"the flag is hkcert24\{a\}"})$. For this method to work, that is to encrypt a message of our choice, we need a xor-pad. This is how we are going to retrieve the pad:
1. Retrieve $ct_1 := \textbf{AES-CTR}(\textbf{"done!"})$ from the output of `finalize_handshake` as Alice.
2. Use the $ct_1$ from previous query to communicate as Bob this time to get $ct_2 := \textbf{AES-CTR}(\textbf{"what is the flag? I have the secret "} \ || \ secret)$. Knowing the secret is unnecessary.
3. Much like the previous step, we send $ct_2$ to Alice and she returns us with $ct_3 := \textbf{AES-CTR}(\textbf{"the flag is hkcert24\{"} \ || \ secret \ || \ \textbf{"\}"})$. This particular secret is what we need.

From $ct_3$ we can deduce the length of the whole flag, as well as get the xor-pad of the portion we know. That is, 
$pad_{1 .. 21} = ct_{3_{1 .. 21}} \oplus \text{"the flag is hkcert24\\{"}$. The later parts of the the ciphertext ($ct_{22..}$) is of no use at this particular moment, since we don't know the later portions of the flag itself. But we are indeed going to make proper use of it later as we shall see in a bit.

We now have what we need to start "guessing" the flag.

### Guessing the flag : one character at a time

Since we know the prefix already, we will start guessing from after that portion, up until the "}". Our goal is to get the $22nd$ character of both the plaintext and the xor pad. The way my idea works is to retrieve the xor pad first, and from that retrieve the flag character.

*For the sake of explanation, let us assume that the 22nd pad character was 'G'. In reality, it can take any values from 0 to 255.*



| $pad_{22}$ | $pad_{22} \ \oplus \ \\}$ | $ct$ | $decrypted$ | $match \ regex$ |
|------------|--------------------------|------|-------------|----------------|
| A | < | <span style="white-space:nowrap">`[KNOWN ENCRYPTED]  \|\|  <` </span> | <span style="white-space:nowrap">`the flag is hkcert24{{`</span> | ❌ |
| B | ? | <span style="white-space:nowrap">`[KNOWN ENCRYPTED] \|\|  ?` </span> | <span style="white-space:nowrap">`the flag is hkcert24{x`</span> | ❌ |
| C | > | <span style="white-space:nowrap">`[KNOWN ENCRYPTED] \|\|  >` </span> | <span style="white-space:nowrap">`the flag is hkcert24{y`</span> | ❌ |
| ... | | | | |
| G | : | <span style="white-space:nowrap">`[KNOWN ENCRYPTED] \|\|  :` </span> | <span style="white-space:nowrap">`the flag is hkcert24{}`</span> | ✅ |
| H | 5 | <span style="white-space:nowrap">`[KNOWN ENCRYPTED] \|\|  5`</span> | <span style="white-space:nowrap">`the flag is hkcert24{r`</span> | ❌ |
| ... | | | | |

We can observe from the table that only for the correct guess of $pad_{22}$ i.e. G did we get a decrypted text adhering to the correct regex format (`hkcert24{.*}`). All other format would yield an incorrect message. That is, the response we are going to get back from the server is like this:

$$
\textbf{response}^{\text{Byron}}(ct \ || \ x) = 
\begin{cases}
\begin{aligned}
&\textbf{AES-CTR}(\text{"nice flag!"})  \ \ &&if  \ x  \ =  \ G \\
&\textbf{AES-CTR}(\text{"too bad..."})  \ \ &&otherwise
\end{aligned}
\end{cases}
$$

Once we do get $pad_{22}$, gettting $pt_{22}$ is rather trivial. Because $pt_{22} = pad_{22} \oplus ct_{22}$. This $ct_{22}$ came from the xored ciphertext we stored earlier.

But... there is a catch though. In order to check if we guessed right, we need to understand if the server responded with $\textbf{AES-CTR}(\text{nice flag!})$, or did it repond with $\textbf{AES-CTR}(\text{too bad...})$ instead. This is a challenging task as we don't have any means in front of us to decrypt the ciphertext. Moreover, we can't take advantage of the length of the ciphertext, since both of them has $10$ characters each. So there's no apparent method to distinguish between them right?

### Distinguish between 'nice flag!' and 'too bad...'

Let $r_1 := \textbf{AES-CTR}(\text{nice flag!})$ and $r_2 := \textbf{AES-CTR}(\text{too bad...})$. Whatever response $r$ we got for our guess of $pad_{22}$, we send it to Alice now. 

```python
        elif self.id == 'Alice':
            if incoming_message == f'what is the flag? I have the secret {self.other_secret}'.encode():
                outgoing_message = f'the flag is {self.secret}'.encode()
            elif incoming_message == b'nice flag!':
                outgoing_message = b':)'
            elif incoming_message == b'too bad...':
                outgoing_message = b'what happened?'
            else:
                outgoing_message = b'???'
```

There can be $2$ outcomes based on what we sent.

$$
\textbf{response}^{\text{Alice}}(r) = 
\begin{cases}
\begin{aligned}
&\textbf{AES-CTR}(\text{":)"})  \ \ &&if  \ r  \ =  \ r_1 \\
&\textbf{AES-CTR}(\text{"what happened?"})  \ \ &&if  \ r  \ =  \ r_2
\end{aligned}
\end{cases}
$$

**That is, for the right guess, we are going to have a cipher text of length of $3$, whereas a wrong guess would give us a ciphertext of length $14$ instead. This difference in length confirms the validity of our guess.**

<div style="text-align: center;">
  <img src="https://github.com/Tsumiiiiiiii/Tsumiiiiiiii.github.io/blob/main/content/posts/HKCERT/flow.svg?raw=true"
       style="max-width: 875px; width: 100%; height: auto;" alt="Centered responsive image" />
</div>

We can further extend this strategy to bruteforce the remaining pad and the flag.
    
### Race against 🕑 : Speeding things up
    
The approach mentioned in the last step works just fine, and given enough time, it will eventually finish guessing all the characters. How much time this whole process would take depends on the internet connection, which, in my laptop was projected to be someting close to an hour and a half. This is fine in most cases, but can be further improved using a well known trick called "batching". Batching is especially useful when you are allowed to "communicate" with a server instance.
    
In this problem, to bruteforce for a character at a particular position, we need $256$ interactions with the server (as there are $256$ possible options for the pad character). Let us try to make a rough "estimate" how much time this would cost.
    
Assume we need to make $256$ queries, and for each query, the **request** takes $50$ ms, and the **network overhead** (Latency) costs $100$ms per query. This means, for when we do queries individually like this, the total time taken would amount to, $T_{\textbf{individual}} = 256 \cdot (50 + 100) = 38400 ms = 38.4 s$.
    
{{< mermaid >}}
sequenceDiagram
    participant User
    participant Server
    User->Server:Query 1
    Note right of Server: Latency
    Server->User: Response 1
    User->Server: Query 2
    Note right of Server: Latency
    Server->User: Response 2
{{< /mermaid >}}

One the other hand, we could "batch" our queries. Suppose we divide our 256 queries into batches (say $64$ queries per batch). And since the total requests to the server is reduced, this would significantly reduce the network overhead, at the cost of increasing batch requests time. Suppose the **batch request** time is $300$ms per batch. That mean the total time incurred due to batching is, $T_{\textbf{batch}} = \frac{256}{64} \cdot (300 + 100) ms = 1600ms = 1.6s$.
    
We reduced the time from more than half a minute to barely a second and a half. This is a drastic improvement, and can be understood even better when the number of queries increases. A chart for comparison:
    
![batching performance chart](https://docs.google.com/spreadsheets/d/e/2PACX-1vTJBLCsa7y604nCJXenD_SpE091vSADJGlkIXwq3w1ZAnpsHD2_Z51WnVw-jfGg3GvkviL2tCopXBIC/pubchart?oid=776153530&format=image)
    
### Finshing things off
    
All that is left is to code everything explained so far, and the flag is ours!
    
```python
import socket
import ssl
import json
import hashlib
from Crypto.Cipher import AES
from tqdm import tqdm

class SecureSocket:
    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port
        self.context = ssl.create_default_context()
        self.sock = socket.create_connection((self.hostname, self.port))
        self.ssl_sock = self.context.wrap_socket(self.sock, server_hostname=self.hostname)

    def recvline(self):
        """Receives data until a newline character is encountered."""
        line = b""
        while True:
            char = self.ssl_sock.recv(1)
            if not char or char == b"\n":
                break
            line += char
        return line

    def recvuntil(self, delimiter):
        """Receives data until the specified delimiter is found."""
        data = b""
        while not data.endswith(delimiter):
            chunk = self.ssl_sock.recv(1)
            if not chunk:
                break
            data += chunk
        return data

    def sendline(self, data):
        """Sends data followed by a newline character."""
        if isinstance(data, str):
            data = data.encode()
        self.ssl_sock.sendall(data + b"\n")

    def close(self):
        """Closes the SSL and underlying socket connection."""
        self.ssl_sock.close()
        self.sock.close()

r = SecureSocket('c24b-pigeon-2.hkcert24.pwnable.hk', 1337)

def receive():
    #return r.recvline()
    res = r.recvline().decode().strip()
    return json.loads(res)

def send(target, req):
    j = json.dumps(req, separators=(',', ':'))
    r.recvuntil(f'🕊️ '.encode())
    r.sendline(f'{target} {j}'.encode())

def process_buffer(buffer):
    to_send = []
    for target, req in buffer:
        j = json.dumps(req, separators=(',', ':'))
        to_send.append(f'{target} {j}'.encode())
    to_send = b'\n'.join(to_send)
    r.sendline(to_send)
    ret = []
    for _ in range(len(buffer)):
        res = r.recvline().decode().strip().replace('🕊️  ', '')
        ret.append(json.loads(res))
    return ret


# cryptographic toolbox

def xor(sa, sb, lenient = 0):
    if not lenient: assert len(sa) == len(sb), f"sa={len(sa)}, sb={len(sb)}"
    return bytes([a ^ b for a, b in zip(sa, sb)])

def encrypt(pt, pad, nonce):
    return nonce + xor(pt, pad)

def verify(ct):
    send('alice', {"type":"communicate", "ciphertext": ct.hex()})
    ct = receive()['ciphertext']
    return len(bytes.fromhex(ct)) == 10

print(receive())
print(receive())
ct = bytes.fromhex(receive()['ciphertext'])
send('byron', {"type":"communicate", "ciphertext": ct.hex()})
ct = bytes.fromhex(receive()['ciphertext'])
send('alice', {"type":"communicate", "ciphertext": ct.hex()})
ct = bytes.fromhex(receive()['ciphertext'])
print(len(ct))
nonce, e_ct = ct[:8], ct[8:]
base = b'the flag is hkcert24{'
pad = xor(e_ct[:len(base)], base)

for i in tqdm(range(75 - len(base))):
    buffer = []
    for opt in range(256):
        to_send = encrypt(base, pad, nonce) + bytes([opt])
        buffer.append(('byron', {"type":"communicate", "ciphertext": to_send.hex()}))

    cts = process_buffer(buffer)
    for opt, ct in enumerate(cts):
        ct = bytes.fromhex(ct['ciphertext'])
        if verify(ct):
            actual = bytes([opt ^ ord('}')])
            pad += actual
            base += bytes([opt ^ ord('}') ^ e_ct[len(base)]])
            print()
            print(base)
            break

#hkcert24{0n3_c4n_4ls0_l34k_1nf0rm4710n_fr0m_th3_l3n9th}
```
