import pwn
import pwnlib
import itertools

words = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_1234567890'

if __name__ == '__main__':
    for i in range(1, 30):
        for word in itertools.product(words, repeat=i):
            p = pwn.process('./void-1b63cbab5d58da4294c2f97d6b60f568')
            p.sendline(''.join(word))
            print p.recvall()
