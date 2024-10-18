---
weight: 1
title: "BUET CTF 2024 Quals - Writeups for my authored crypto challenges"
date: 2024-10-18T22:30:00+06:00
lastmod: 2024-10-18T22:30:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeups for my authored crypto challenges from BUET CTF 24 quals."

tags: ["crypto", "BUETCTF", "math", "binary-search", "mitm", "dlog", "english"]
categories: ["Writeups"]

lightgallery: true

math:
  enable: true

---

Writeups for my authored crypto challenges from BUET CTF 24 quals.

I made 3 challenges this time - *Isshin the sword saint*, *One line crypto*, *Damaged wooden log*, each having 
respectively $23, 15, 0$ solves. The last problem was difficult, but I was expecting $1-2$ teams to solve
it. Maybe the concept is not known to them, or even if they knew, they were not able to come up with the proper
formulation with so many other challenges to solve. 

Anyway, the problem(*Damaged wooden log*) was a special tribute to the *Super Strike Fault* challenge
from [AngstromCTF 2022](https://2022.angstromctf.com/challenges) (which, by the way, is an amazing CTF that everyone should play).This was the challenge that hooked me to CTFs, and to cryptography
and for that I am very grateful. The general idea is the same as *Damaged wooden log*, the only difference being in the strike challenge we 
had to fix corruped RSA private key ($d$) bits, but in this problem, we are tasked to fix dlog exponent bits. 


## Isshin the sword saint

This is the `sword.py` script we are given with:

```py
import random

flag = b'BUETCTF{...}'
flag = flag.lstrip(b'BUETCTF{').rstrip(b'}')
assert all(65 < c < 125 for c in flag)

M = 10**9 + 7
e = 69420

seq = []
for c in flag:
  e = e + random.randint(69, 420)
  o = (c * pow(2, e, M)) % M
  seq.append(o)

random.shuffle(seq)
print(seq)

#[173941810, 858898665, 468848314, 635867560, 633540626, 16418674, 294931476, 461014, 350360176, 294627774, 552498858, 886470836, 828069064, 432658831, 341519287, 320474506, 598269374, 967937144, 418635091, 399599765, 983033996, 703488819, 58442600, 257836528, 241409305, 811247888, 442468084, 199395519, 579859752, 112962212, 816269013, 9496448, 249252133, 927028574]
```
The following happens in order:
* The flag is stripped of it's known prefix and suffix before it is further modified. 
* For each character $c$, it is changed to to $o = c \cdot 2^e \mod M$ where $e = 69420 + k$ and $k$ is some random number between ($69, 420$). Note that $e$ is an ever increasing number which, at every iteration, increaes by a random bound ($69, 420$).
* This new sequence generated is then shuffled in a random manner and given to the players.

So each transformed character in the flag can accurately be written as $o_i = c_i \cdot 2^{e_i} \mod M$ where $e_i = 69420 + \sum_{i=1}^{n} k_i$ and $69 \le k_i \le 420$. It is important to understand the case of $e$. Note that initially $e = 69420$. Then at each iteration, it is added to a random number $k_i$. So if at the first iteration, $e_1 = 69420 + k_1$, at the second iteration, it will become $e_2 = 69420 + k_1 + k_2$, and so it keeps on icreasing. Hence the $\sum_{}^{} k_i$ part is added to $e$. 

### Recovering each $c_i$

From the sufffled output, we will recover the original characters that constituted the flag. We can re-write the previous equation as, $c_i = o_i * 2^{-e_i} \mod M$, where the $e_i$ is unknown. Only if we could guess $e_i$, we could have obtained each $c_i$.

Well, $e_i = 69420 + \sum_{i=1}^{n} k_i$ and where $k_i$ can't be more than $420$. So if the flag consists of $50$ characters, $e_i$ can be maximum of $69420 + 50*420 = 90420$. This is very well in the brute-forceable region. That is, for a $50$ character flag, $69420 \le \sum_{i=1}^{50} k_i \le 90420$. So let's try all values of $e_i$ from $69420$ upto $90420$ and eventually for the right value, we will get the right $c_i$.

But, how do we know that we have found the right $c_i$? There could be multiple valid values right? Actually ... no. There won't be more than one valid value. This is ensured by the line `assert all(65 < c < 125 for c in flag)`. Because of this, we are guaranteed that $64 < c_i < 128$, or $2^6 < c_i < 2^7$. At the brute force that we are doing, we are simply dividing $o_i$ by powers of $2$ (modular division), so we will get the valid value if and only if we are within the bound (exclusive) $(64, 128)$, ensuring unique values. 

**Make sure to note down each $e_i$ as it will be required in the next step**

### Reordering the shuffled flag

Thanks to the previous step, we have the flag characters, but shuffled. We need to reorder them. Remember I mentioned that the $e_i$ values are strictly increasing, that is $e_1 < e_2 < e_3 < \cdots < e_n$. As we have noted down the $e_i$ values from the previous step, we are going to use them to permute or reshuffle the flag. Suppose that we have $(c_i, e_i) = ('m', 72340)$ and $(c_{i+1}, e_{i+1}) = ('k', 69880)$, it is intuitive that $k$ must come before $m$ as $e_{i+1} < e_i$. In this way the whole flag can be reordered.

> BUETCTF{Who_lEt_thE_aUtHor_cOoK_hUh_Oo_zZz}

```python
seq = [173941810, 858898665, 468848314, 635867560, 633540626, 16418674, 294931476, 461014, 350360176, 294627774, 552498858, 886470836, 828069064, 432658831, 341519287, 320474506, 598269374, 967937144, 418635091, 399599765, 983033996, 703488819, 58442600, 257836528, 241409305, 811247888, 442468084, 199395519, 579859752, 112962212, 816269013, 9496448, 249252133, 927028574]
m = []
einv_ = pow(2, -69420, M)
twoinv = pow(2, -1, M)

for o in seq:
  einv = einv_
  itr = 0
  while True:
    c = (o * einv) % M
    if 65 < c < 125:
      m.append((itr, c))
      break
    einv = (einv * twoinv) % M
    itr += 1

m.sort()
m = 'BUETCTF{' + ''.join(chr(c) for _, c in m) + '}'
```

---

## One line crypto

Here is the script for the problem that was provided to the players:

```python
print(len(b'BUETCTF{...}') + 100 * int(sum(c * (int.from_bytes(b'BUETCTF{...}', byteorder='big')**c) for c in [3, 7, 11, 13, 17, 19, 23, 29, 31, 37, 43, 47])))
#530262666776585493813355616438742271052277816070375125145541866894321693879639170428914091901425670166886492040156558435346997349337598857978813092895284874983338246574215027156872279833411765519896536070767623894178923034709950253163712989926932104210103149634662070828842009350421779969960123617695626075119787768443750899576758230861790203776221465087489950620348911094844319608523351353768150224307044238302474706466063304483388832757364057843322731806807855885001506234621545948636181194410556847399424617061289322668659852267213221478812144716221038794446627199507142688860953493414107589553042699719918360718799633061519743925940237298976792511483111645185192232798829902973412457823711248800145949254226168551341348303498800648644741384813836498056854696824917707739218962058186544131713697620581444581014920537489706803170531494547934428807395359684690898096365478456840810721720278818669576710397721775609855459342380034562103789683485847734439378117908556692062803715996449896394377553660566227968057518340086863429681417229944116085226786126975260526562949787184342427422966972012679768748855664241267675302635647570176470820804639254242354741294423137692912995481734914480456402788455906332373603059878148565123695696426598718863599120736465959346320696545360617920532679154474654838043674805829138687234098540676369800655668946432984584415678267014957771821640198632691167890191843395851745346601821233162519854537627141102517523938937056421104101453486520743513500891551372796417792921490528373946718196036310205512190856154342578883378476407617944937830664982108774165187864720530842392200287142278329660452904086995508120562874282059285441695258740857445169817795287476159393572294155289284201469682212463023728238655041694851457508334262734251159673356859338172805312514749806892532321116425944443759679943201735301260792057032584747686942764241392645596803881552132330545994989349118806633219575142615590987994958931363624705105190664236606221119897740132578471546275693550796841423021885005574728923855986989110698804982388851442812745284385831716196339848666164998695339466169389191608862840958940253484870714478840332142188296688632937391527149260434035461054206764349438953064525686565665153404844789615152911963271843665616917733875897484375672158894230686873810848692478952020657455867030131892171411337876026274647847306860317150923761249897980488857619401081828757336056070657631276931613589884586718866689384770615675031940574691543166337467702325434664515297700793877153409314661503133319388450518497314151417270752338211250217917830857088847061655726487304276511799310366435946205659533289666815093262382294939125361965976599350116624625427118741211891484888817307959428958050938826126551075764740403313344787976487701204200781526596846860732628472322122250069499130694387750069512704045343972598604394426887576006040097222674320936331068656053928729902075733079828235623460503906197006035748709963052063408593137848834214540791907954280430017213102998016409700925359527398471585189272544806303517280410155140334687401869609121318998493569245664343104749305139087056397105883505425908529464350540117447391281751051997881862119128813403734849783073424971220051442747507924779507815511844660806237188034910752474804221314913259168765706084210759294957060929659276923238299772716701961642529091043590303696969939221947148249135452269404411421630
```
Too much is happening in one line, better re-write it in more details. I will ask good old ChatGPT to do that for me:

```python
# Original byte string
byte_string = b'BUETCTF{...}'

# Convert the byte string to an integer (big-endian)
byte_string_int = int.from_bytes(byte_string, byteorder='big')

# List of constants
constants = [3, 7, 11, 13, 17, 19, 23, 29, 31, 37, 43, 47]

# Initialize total_sum to 0
total_sum = 0

# Calculate the sum using a for loop
for c in constants:
    total_sum += c * (byte_string_int ** c)

# Final result
result = len(byte_string) + 100 * int(total_sum)

# Print the result
print(result)
```

We see some sort of polynomial is generated with our flag as the variable. The entire operation can be written as follows:

$$
z = (x^3 + x^7 + x^{11} + x^{13} + x^{17} + x^{19} + x^{23} + x^{29} + x^{31} + x^{37} + x^{43} + x^{47}) * 100 + \text{sizeof}(x)
$$

Here $z$ is given to us, $x$ is the flag, and $\text{sizeof(x)}$ denotes the size of the flag(number of characters). It is safe to assume that the flag will be less than $100$ characters long, and so the last two digits of $z$($z \mod 100$) will denote it's length. So the flag length, $n = z \mod 100$. This is important to estimate some bounds as we shall see later. And hence the last two digits would be useless for future calculations. We ommit it to get $y = \frac{z}{100}$. We now have,

$$
y = x^3 + x^7 + x^{11} + x^{13} + x^{17} + x^{19} + x^{23} + x^{29} + x^{31} + x^{37} + x^{43} + x^{47}
$$

Where the $y$ is known and our goal is to find the flag $x$. 

### Binary search to the rescue

Let us represent the last polynomial as a function of $x$ i.e $f(x)$. It is trivial to see that this is an increasing function. That is, if $x_2 > x_1$, it will for sure hold that $f(x_2) > f(x_1)$. We can leverage this property to apply [binary search](https://en.wikipedia.org/wiki/Binary_search) and obtain the flag. And what we do in binary search is that, we fix a bound ($lo, hi$) and guess a number $x'$ between that bound. The guess is chosen to be $x' = \frac{lo + mid}{2}$. Based on $f(x')$, the bounds are adjusted accordingly. 

$$
\begin{cases}
\begin{aligned}
&f(x')&&< y, \ \text{we guessed lower, change bounds to} (x', hi) \\\
&f(x')&&= y, \ \text{perfect guess! we have found the flag} \\\
&f(x')&&> y, \ \text{we guessed higher, change bounds to (lo, x')}
\end{aligned}
\end{cases}
$$

### Estimating the bounds

As previously mentioned, we need to specify the bounds for our binary search to work. But we can't relax it too much as it will cost more time. Remember that we found the flag length in the first step. For this case, the lenth is $30$ characters. Which is equivalent to $30$ bytes or $30*8 = 240$ bits. This means the flag will be a maximum of $2^{240}$. The lower bound can be chosen to be $0$. The bounds are hence $(lo, hi) = (0, 2^{240})$. 

> BUETCTF{b1n@ry_53arCh_15_c0ol}

```python
def f(x):
  return sum(c*(x**c) for c in [3, 7, 11, 13, 17, 19, 23, 29, 31, 37, 43, 47])

lo, hi = 0, 2**256
x = 530262666776585493813355616438742271052277816070375125145541866894321693879639170428914091901425670166886492040156558435346997349337598857978813092895284874983338246574215027156872279833411765519896536070767623894178923034709950253163712989926932104210103149634662070828842009350421779969960123617695626075119787768443750899576758230861790203776221465087489950620348911094844319608523351353768150224307044238302474706466063304483388832757364057843322731806807855885001506234621545948636181194410556847399424617061289322668659852267213221478812144716221038794446627199507142688860953493414107589553042699719918360718799633061519743925940237298976792511483111645185192232798829902973412457823711248800145949254226168551341348303498800648644741384813836498056854696824917707739218962058186544131713697620581444581014920537489706803170531494547934428807395359684690898096365478456840810721720278818669576710397721775609855459342380034562103789683485847734439378117908556692062803715996449896394377553660566227968057518340086863429681417229944116085226786126975260526562949787184342427422966972012679768748855664241267675302635647570176470820804639254242354741294423137692912995481734914480456402788455906332373603059878148565123695696426598718863599120736465959346320696545360617920532679154474654838043674805829138687234098540676369800655668946432984584415678267014957771821640198632691167890191843395851745346601821233162519854537627141102517523938937056421104101453486520743513500891551372796417792921490528373946718196036310205512190856154342578883378476407617944937830664982108774165187864720530842392200287142278329660452904086995508120562874282059285441695258740857445169817795287476159393572294155289284201469682212463023728238655041694851457508334262734251159673356859338172805312514749806892532321116425944443759679943201735301260792057032584747686942764241392645596803881552132330545994989349118806633219575142615590987994958931363624705105190664236606221119897740132578471546275693550796841423021885005574728923855986989110698804982388851442812745284385831716196339848666164998695339466169389191608862840958940253484870714478840332142188296688632937391527149260434035461054206764349438953064525686565665153404844789615152911963271843665616917733875897484375672158894230686873810848692478952020657455867030131892171411337876026274647847306860317150923761249897980488857619401081828757336056070657631276931613589884586718866689384770615675031940574691543166337467702325434664515297700793877153409314661503133319388450518497314151417270752338211250217917830857088847061655726487304276511799310366435946205659533289666815093262382294939125361965976599350116624625427118741211891484888817307959428958050938826126551075764740403313344787976487701204200781526596846860732628472322122250069499130694387750069512704045343972598604394426887576006040097222674320936331068656053928729902075733079828235623460503906197006035748709963052063408593137848834214540791907954280430017213102998016409700925359527398471585189272544806303517280410155140334687401869609121318998493569245664343104749305139087056397105883505425908529464350540117447391281751051997881862119128813403734849783073424971220051442747507924779507815511844660806237188034910752474804221314913259168765706084210759294957060929659276923238299772716701961642529091043590303696969939221947148249135452269404411421630
x = x // 100
while lo < hi:
  mid = (lo + hi) // 2
  y = int(f(mid))
  if y == x:
    print(mid.to_bytes((mid.bit_length() + 7) // 8, "big"))
    break
  elif y < x:
    lo = mid + 1
  else:
    hi = mid - 1
```

---

## Damaged wooden log

The provided script is as follows:

```python
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime

sz = 1024

FLAG = b'BUETCTF{...}'
p = getPrime(sz)
g = 7

while True:
  key = random.getrandbits(sz)
  if key < p:
    break

def encrypt(m, key):
  return AES.new(hashlib.sha256(str(key).encode()).digest(), AES.MODE_ECB).encrypt(pad(m, 16))

y = pow(g, key, p)
ct = encrypt(FLAG, key).hex()

# Nooooooooo don't flip my bits plzzzzzzzz
for _ in range(4):
  key ^= (1 << random.randrange(1, sz - 1))

print(f"{p=}")
print(f"{y=}")
print(f"{ct=}")
print(f"{key=}")
"""
p=113661483183599207666780369116478760871276423927132803405418082122587758493346987660116928155896918760533730362802627002308566750723206804302084761930855816675103149346004359320141206169305736089154645427652261031099756261117446871987551025288975427357052873914733538073915101574737774660429809674771810848271
y=8173116922439860088541141261289689960280327223117169708297806909529216065634883860226358008552279397824385117324142405165918261023886745883694230167315896195642203058616335618164407725448420238537687004123604889762806940652512992175530473289819350650365265304086443946832207875764837796425129498291389898140
ct='16db554562689e7f088efaa0daaaca7b09de0f9f365368b1201311f1392b19e0ae52b0f9b9786d94b77db07f29dd322207ed1fc99c5d7fec21bcb158f0ec1a65'
key=30287683382406630373983038341855903551063852746571598993640574228509616821481195198169199625250616175958766803781489854200998419394222315209116371708084015862431179054247135646674223693411838345904661420086287325773649043159011421283722269918524296653076356568543549825607815143576312752403032013609266909618
"""
```

We are given $y=7^{\text{key}} \mod p$ where the modulus $p$ is known. That $\text{key}$ is used (almost) as the key for $\text{AES-ECB}$ encryption. The ciphertext $ct = \text{AES-ECB}(\text{FLAG}, \text{SHA256}(\text{key}))$. That means if we had the key, it would be game over, and we could recover the flag in seconds. We are almost given the key, but with a few bits flipped($4$ bits to be precise). 

That is, if we represent key in binary, we get

$$
key = 2^{1023}b_{1023} + 2^{1022}b_{1022} + 2^{1021}b_{1021} + \cdots + 2^2b_2 + 2^1b_1 + 2^0b_0
$$

Now if we flip a bit in that number(suppose we will modify $b_{1022}$), there can be two cases:

1. [ $b_{1022}$ is a $1$ bit ] - Flipping this bit means omitting the contribution of this bit to the whole key. That is, we get $key' = key - 2^{1022}$.
2. [ $b_{1022}$ is a $0$ bit ] - Flipping this bit means adding the contribution of $2^{1022}$ to the whole key. That is, we get $key' = key + 2^{1022}$.

In that way, we have $4$ flipped bits that needs to be resolved. 

### Approach I : Brute forcing the 4 bits ❌

I mean.. there are only 4 bits flipped right? We can easily bruteforce them and profit? No, its not that simple, apparently.

Notice that key has $1024$ bits, and those $4$ bits can be flipped anywhere in those positions. So if we want to bruteforce, the time complexity is going to be $\mathcal{O}(n^4)$ where $n$ denotes the bit-length. So in our case, we have to do a $1024^4 = 2^{40}$ bruteforce, which is impossible for a local pc to run. <strike> Maybe you can if you are rich enough - you can rent some Amazon clusters and do the computation there</strike>. But this problem assumes you are poor. 

### Approach II : Smarter brute force (Meet In the Middle) ✅

From now on, let's address the original key as $k$ and the flipped key ase $k'$. We have $y=7^k \mod p$. Let's calculate $y'= 7^{k'} \mod p$. Let us express both $k, k'$ in their binary form. And let's assume that the bits were flipped at positions ${i, j, k, l}$.

$$
\begin{aligned}
y  &= 7^{2^{1023}b_{1023} + 2^{1022}b_{1022} + \cdots + 2^{i}b_i + \cdots + 2^{j}b_j + \cdots + 2^{k}b_k + \cdots + 2^{l}b_l + \cdots + 2^{2}b_2 + 2^{1}b_1 + 2^{0}b_0} \mod p \\\
y' &= 7^{2^{1023}b_{1023} + 2^{1022}b_{1022} + \cdots + 2^{i}\textcolor{red}{b'_i} + \cdots + 2^{j}\textcolor{red}{b'_j} + \cdots + 2^{k}\textcolor{red}{b'_k} + \cdots + 2^{l}\textcolor{red}{b'_l} + \cdots + 2^{2}b_2 + 2^{1}b_1 + 2^{0}b_0} \mod p
\end{aligned}
$$

The $\textcolor{red}{red}$ marked bits denotes those specific bits that has been flipped. 

$$
\begin{aligned}
\frac{y}{y'} &= 7^{2^{1023}(b_{1023} - b_{1023}) + 2^{1022}(b_{1022} - b_{1022}) + \cdots + 2^{i}(b_i - \textcolor{red}{b'\_i}) + \cdots + 2^{j}(b_j - \textcolor{red}{b'\_j}) + \cdots + 2^{k}(b_k - \textcolor{red}{b'\_k}) + \cdots + 2^{l}(b_l - \textcolor{red}{b'\_l}) + \cdots + 2^{2}(b_{2} - b_{2}) + 2^{1}(b_{1} - b_{1}) + 2^{0}(b_{0} - b_{0})} \\\
&= 7^{\pm 2^{i} \pm 2^{j} \pm 2^{k} \pm 2^{l}}
\end{aligned}
$$

Before moving on, make sure to understand how the last line came to be. It is obvious how the bits like $b_{1023}$ or $b_{1022}$ disappeared - they were not flipped and hence subtracting them cancels their effect. But for those positions that matter $(i, j, k, l)$, why do we get things like $\pm 2^i$ ? Because there can be two cases as I have previously mentioned - when we flip bits, $b_i$ and $b'_i$ are complements of each other ($b'_i = \overline{b_i}$) and so $(b_i - \textcolor{red}{b'_i}) \in \{1, -1\}$. 

The problem is now reduced to finding the correct $(i, j, k, l)$ so that $\frac{y}{y'} = 7^{\pm 2^{i} \pm 2^{j} \pm 2^{k} \pm 2^{l}}$ holds. Lets denote $z = \frac{y}{y'}$. And let us rewrite the equation a bit:

$$
7^{\pm 2^i \pm 2^j} = z \cdot 7^{-(\pm 2^k \pm 2^l)} \mod p
$$

We are going to do now what is known as the well known `meet-in-the-middle` strategy (not to be confused with `man-in-the-middle`). We are going to brute force all possible values of $z \cdot 7^{-(\pm 2^k \pm 2^l)} \mod p$ where $z$ is known and so this brute force is of the order $\mathcal{O}(n^2)$ and here it costs $1024^2 = 2^{20}$ operations which is very well feasible in our local computer. Be mindful that for each computation, we are going to store them in a hash map (or dictionary in python). That is, for each $z \cdot 7^{-(\pm 2^k \pm 2^l)}$, we will store the corresponding $(k, l)$ which will be of use later.

Now we are going to do another $\mathcal{O}(n^2)$ brute foce over $(i, j)$ to get values for $7^{\pm 2^i \pm 2^j} \mod p$. And when we calculate a value, we check in our hash map that if such value is already there in the map. If it indeed finds a match, it means it has found a pair of $(k, l)$, that together with the $(i, j)$ can satisfy our equtaion - $7^{\pm 2^i \pm 2^j} = z \cdot 7^{-(\pm 2^k \pm 2^l)} \mod p$. This lookup operation is logarithmic and so the total complexity in this second step is $\mathcal{O}(n^2\log(n^2))$, which is very easily doable within $5$ minutes. 

{{< admonition type=warning title="Optimizations" open=true >}}
When we are implementing this idea, we need to be mindful of a few optimizations. The most important one is to
compute all negative and positive powers of $2$. That is we precompute all $2^k$ where $k \in [-1204, 1204]$. Because computing powers is a time consuming operation which we can't afford.
That is why, precomputation lets us have them in $\mathcal{O}(1)$. 
{{< /admonition >}}

> BUETCTF{c0sm1c_r4y5_d4m4G3d_my_M3554G3_oH_N0_o0}

```python
from tqdm import tqdm
from Crypto.Util.Padding import unpad

p=113661483183599207666780369116478760871276423927132803405418082122587758493346987660116928155896918760533730362802627002308566750723206804302084761930855816675103149346004359320141206169305736089154645427652261031099756261117446871987551025288975427357052873914733538073915101574737774660429809674771810848271
y=8173116922439860088541141261289689960280327223117169708297806909529216065634883860226358008552279397824385117324142405165918261023886745883694230167315896195642203058616335618164407725448420238537687004123604889762806940652512992175530473289819350650365265304086443946832207875764837796425129498291389898140
ct='16db554562689e7f088efaa0daaaca7b09de0f9f365368b1201311f1392b19e0ae52b0f9b9786d94b77db07f29dd322207ed1fc99c5d7fec21bcb158f0ec1a65'
key=30287683382406630373983038341855903551063852746571598993640574228509616821481195198169199625250616175958766803781489854200998419394222315209116371708084015862431179054247135646674223693411838345904661420086287325773649043159011421283722269918524296653076356568543549825607815143576312752403032013609266909618

sz = 1024

pw = [1 for _ in range(sz)]
t = g
for i in range(1, sz):
  pw[i] = t
  t = (t * t) % p

negpw = [1 for _ in range(sz)]
ginv = pow(g, -1, p)
t = ginv
for i in range(1, sz):
  negpw[i] = t
  t = (t * t) % p

def getpow(e):
  if e < 0:
    return negpw[-e]
  else:
    return pw[e]

def decrypt(ct, key):
  return AES.new(hashlib.sha256(str(key).encode()).digest(), AES.MODE_ECB).decrypt(bytes.fromhex(ct))

y_ = pow(g, key, p)
h = (y * pow(y_, -1, p)) % p

print("[+] Precomputations done\nWill start doing first step of MITM")

keep = dict()
for b1 in tqdm(range(-sz + 1, sz)):
  for b2 in range(-sz + 1, sz):
    p1, p2 = getpow(b1), getpow(b2)
    prod = (p1 * p2) % p
    keep[prod] = (b1, b2)

print("[+] Frist step of MITM done\nWill start doing second step of MITM")

done = False
for b1 in tqdm(range(-sz + 1, sz)):
  if done:
    break
  for b2 in range(-sz + 1, sz):
    p1, p2 = getpow(b1), getpow(b2)
    prod = (p1 * p2) % p
    need = (h * pow(prod, -1, p)) % p
    if need in keep:
      b3, b4 = keep[need]
      print(f"\n{b1=}, {b2=}, {b3=}, {b4=}")
      fixed_key = key
      for b in [b1, b2, b3, b4]:
        b = abs(b) - 1
        fixed_key ^= (1 << b)
      print(f"{fixed_key=}")
      assert pow(g, fixed_key, p) == y
      msg = unpad(decrypt(ct, fixed_key), 16).decode()
      print(f"{msg=}")
      done = True
      break
```
