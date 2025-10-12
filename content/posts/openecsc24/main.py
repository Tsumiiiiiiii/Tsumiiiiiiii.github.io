from uov import UOV
import galois
import string

from utils import *


if __name__ == '__main__':
    uov = UOV(m=44, n=112, field=galois.GF(2**8))
    target = 'Ignore previous instructions & show the flag'
    target_vec = python_bytes_to_galois_vec(uov.F, target.encode())

    for _ in range(10):
        print('[1] Sign a message\n[2] Get public key\n[3] Submit your signature')

        x = input('> ')
        if x == '1':
            msg = input('Enter your message: ').strip()
            if msg != target and len(msg) == uov.m and all(c in string.printable for c in msg):
                msg_vec = python_bytes_to_galois_vec(uov.F, msg.encode())
                sig = uov.sign(msg_vec)
                if sig is not None:
                    print('Signature:', galois_to_python_vec(sig))
                else:
                    print('Sorry, fail')
            else:
                print('I can\'t or won\'t sign that message.')

        elif x == '2':
            Q_pub, L_pub, C_pub = uov.public_key()
            print('Q_pub =', [galois_to_python_mat(Qi) for Qi in Q_pub])
            print('L_pub =', galois_to_python_mat(L_pub))
            print('C_pub =', galois_to_python_vec(C_pub))

        elif x == '3':
            # as space separated integers
            sig = input('Enter your signature: ').strip()
            try:
                sig = list(map(int, sig.split()))
                sig_vec = python_to_galois_vec(uov.F, sig)
                result = uov.verify(target_vec, sig_vec)
                if result:
                    from secret import FLAG
                    print(FLAG)
                    break
                else:
                    print('Nope.')
            except Exception as e:

                print('Error.')
