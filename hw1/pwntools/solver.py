from pwn import *

guess_remote = remote('csie.ctf.tw', 10123)

recv = guess_remote.recvline()

# binary search
low = 0
high = 50000000
while low <= high:
    mid = (low + high) // 2
    guess_remote.sendline(str(mid))
    recv = guess_remote.recvline()
    if recv == 'input number = It\'s too small\n':
        low = mid+1
    elif recv == 'input number = It\'s too big\n':
        high = mid-1
    else:
        print(recv)
        break
