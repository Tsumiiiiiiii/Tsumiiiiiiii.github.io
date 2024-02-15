---
weight: 1
title: "Ping CTF 2023 - EASY RSA Writeup"
date: 2023-12-27T22:02:00+06:00
lastmod: 2023-12-27T22:02:00+06:00
draft: false
author: "lolipop"
authorLink: "https://tsumiiiiiiii.github.io"
description: "Writeup for the EASY RSA cryptography challenge."

tags: ["crypto", "RSA", "DFS", "ping CTF", "english"]
categories: ["Writeups"]

lightgallery: true

toc:
  enable: true
---

Writeup for the EASY RSA cryptography challenge.

<!--more-->



We are provided with a very short script:

```python
from Crypto.Util.number import getPrime
from Crypto.Util.number import bytes_to_long

p = getPrime(2048)
q = getPrime(2048)
n = p * q
e = 65537
d = pow(e, -1, (p-1)*(q-1))
flag = open("flag.txt","rb").read()

print(f"q & p = {q & p}")
print(f"q & (p << 1) = {q & (p << 1)}")
print(f"n = {n}")
print(f"ct = {pow(bytes_to_long(flag), e, n)}")
```

And the output:

```python
q & p = 19255533152796212242992720925015052977165100229038356072853122758344297941391913731811288637503889893957835822989935905303713710752777324449266828571841201518847196873248114942547801080335290296371569234716421544911658172501145437393374846710803138137307808989325161763203891991730019545282414118666012446323593086041877728885890674444508568272709108666087094340700674807743690571277087703553222951943577713106957357837938244344527749744370370435090293574356857988176670599582946379436655614131476306476922532815575101035473325680474072477054146850541735494484153707953999275852485352550848613495775319945508202644999
q & (p << 1) = 7112801180654287964416909811366845221897670460107053268303965490368202211276157255630735531566632628465152668686888640536853981159344411188296318259605583929497982211483530931191597394343036880068072881710523781673885424996130058924135020477539221992619498201582190182198153594649904776914100045695897933800407597682900652789330655753567616853658441592170031153228700361032402777562805345962689285290223782295723638984115678627453468399955519885678698327942540059520178138360999657256216711952458812051551165176295610310500428357599329357195749872213722317472180820883692423118643045719988782875815244858084697476366
n = 629263048151678305452575447956575574759729289344426844202876190608729386386187311507156472537419877194722565074742404474698366095301561396335500009086708551715132944925359104482586968535982172950848450616991486882164933308508030447653541771655030633998773150256734151751231794877979894290664805083776347342841761965788022840306507239441472691061434470185155032785918312667155385234312006506953766398470559241684348455601303254513011313918610616344912164305133747945264184175075854717949201043915926552112919719551057640336347310797718453167003130736074852312783981575598197332137858417098138416213397261148554654179742495625000360596380874940069029982601426157700748784881191392765089982233146921318026797755334408105373194190261281426387522068561242744164826397282820570568637958792140799126352243030106388095542265469305391551869027843342339154723022877866472822563864376560243639560467511356673304688994611178354402493975884389423599865545923442816759098328052411030900992085384559185402018882151132333482321734163732964488703573324125780883694828630888629776285568460726623516777110511994045844185435441079697963865653276442218986812145494888396848459290412863370866388156404788872458013848321261694230557300704687955285231150137
ct = 35298631628116130359224654110168305695982263906500815601759249283108606781495993601939607677236970629068001134120097872048346298307953019858839919026717964105487869203149070597551936375993296199579660217021336136433998784937743603970683139418478689946222340268013996123454851821390724257210413455383613162701044471319404611416122452452921345595693933169636951035696702392623767085416101066602717724444002299274612686682594037338907063212581482954711824313661812748820691063881955175084607554637569409759030783300364288473371373832534871778535166888722850811961187103969586607877763143837938758790388347366625971683806113122596153715440188499656167803082999535346051898784036138811121907140409949123154237058329266014568111157279036477684552616957311754125182216065734001391180809071098197495830457756618079294014902429236831364119377802719574368458610707827017826257992031935701095686318205715338591241306163306525299337400170716508041836622056171392705019985962093427177719472269053233585174677794853848800112460097556102315773427435151857478042275125516910669415068837225875052551650890943588902290783802793542904493909655842024149436485583744880955905477870547039491983853968026355806167211650396511235141802512018515691794973835
```

So the information we have is:

$$p \ \\& \ q = p_{2047} \ \\& \ q_{2047} \ \ p_{2047} \ \\& \ q_{2047} \ldots p_1 \ \\& \ q_1 \ \ p_0 \ \\& \ q_0$$

$$q \ \\& \ (p << 1) = q_{2047} \ \\& \ p_{2046} \ \ q_{2046} \ \\& \ p_{2045} \ldots q_2 \ \\& \ p_1 \ \ q_1 \ \\& \ p_0$$

Also, we have $n=p*q$ and let us see how the binary multiplication works here (we have taken two 3-bit primes for demonstration):

![Pasted image 20231227220006](https://github.com/Tsumiiiiiiii/Tsumiiiiiiii.github.io/assets/31077557/50301aad-c8cb-4d96-bf9f-55de522cb754)

We have the observation that the $i-th$ bit of $n$, that is, $n_i$ depends only on those bits $bit_j$ of $p$ and $bit_k$ of $q$ where $i >= j$ and $i >= k$. 

Enough information is now present to use to extract each bit of $p, q$. We start from the LSB. For the $i-th$ bit from the right, there are can 4 case : 2 bits for $p_i$ and 2 bits for $q_i$. We can narrow it to much less amount of cases based on the following information:
1. $p_i \ \ \\& \ \ q_i$
2. $q_i \ \ \\& \ \ p_{i - 1}$
3. The lower $i$ bits of $n$. 

But there might still be some ambiguity at some positions(multiple cases might satisfy) and to mitigate that problem, we can use `depth-first-search` to use all the valid combinations until the full length is enumerated. Only around 30 seconds after running, we can get the flag. Do remember to keep a visited array to stop the infinite recursion from happening.

The solution script is:

```python
import sys
sys.setrecursionlimit(10**6)

from Crypto.Util.number import getPrime
from Crypto.Util.number import long_to_bytes as l2b

sz = 2048
n = ...
ct = ...
r = ...
s = ...

vis = set()
def go(la, lb, cura, curb, idx):
    if (cura, curb) in vis or (curb, cura) in vis: return
    vis.add((cura, curb))
    if idx == sz:
        x = int(cura, 2)
        y = int(curb, 2)
        if n % x == 0:
            p = x
            q = n // p
            phi = (p - 1) * (q - 1)
            e = 65537
            d = pow(e, -1, phi)
            m = pow(ct, d, n)
            print(l2b(m))
        return

    bit1 , bit2 = (r >> idx) & 1, (s >> idx) & 1
    mask = int('1' * (idx + 1), 2)
    nsub = n & mask
    for a in range(2):
        for b in range(2):
            na, nb = int(str(a) + cura, 2), int(str(b) + curb, 2)
            nn = na * nb
            if (a & b == bit1) and (a & int(lb) == bit2) and (nn & mask == nsub):
                go(str(a), str(b), str(a) + cura, str(b) + curb, idx + 1)

go('1', '1', '1', '1', 1)
```